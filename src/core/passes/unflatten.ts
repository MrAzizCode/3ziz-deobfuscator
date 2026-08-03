/**
 * Recover real control flow from a dispatcher-flattened function.
 *
 * These wrappers replace structured code with a state machine:
 *
 *     local W = 31
 *     while true do
 *       if W == 31 then  <block A>  W = 114
 *       elseif W == 114 then <block B>  W = 7
 *       ...
 *     end
 *
 * The blocks are real code in scrambled order; the state variable is the only
 * thing saying how they connect, and its next value is usually hidden behind
 * dense integer arithmetic over a seed table.  Folding that arithmetic with
 * the constant evaluator recovers the edges, which turns the state machine
 * back into a graph that can be read.
 *
 * This analysis is static: it interprets our own AST through `const-eval` and
 * never executes submitted code.  Every step that cannot be proven leaves the
 * state unresolved rather than guessing an edge.
 */

import {
  asStateNumber,
  evaluateConstantExpression,
  integer,
  type LuaValue,
} from "./const-eval";
import { executeStatements, ValueStore } from "./abstract-interpreter";
import type { LuauNode } from "../source/luau-parser";

export interface DispatcherState {
  /** The value of the state variable that selects this block. */
  readonly value: number;
  /** Statements executed while in this state. */
  readonly body: readonly LuauNode[];
  /**
   * States this one can transfer to.  Empty means the successor could not be
   * proven, which is reported rather than filled in.
   */
  readonly successors: readonly number[];
  /** True when the block leaves the dispatcher entirely (break/return). */
  readonly exits: boolean;
}

export interface FlattenedDispatcher {
  /** Name of the variable the dispatcher switches on. */
  readonly stateVariable: string;
  /** Initial value, when it could be proven. */
  readonly entryState: number | null;
  readonly states: readonly DispatcherState[];
  /** States whose outgoing edge could not be resolved. */
  readonly unresolvedStates: readonly number[];
  /** The `while true do ... end` node this was recovered from. */
  readonly loop: LuauNode;
}

export interface UnflattenOptions {
  /** Constants visible to the dispatcher, such as its seed table. */
  readonly scope?: ReadonlyMap<string, LuaValue>;
  readonly maxStates?: number;
}

const DEFAULT_MAX_STATES = 4_096;

/**
 * Bind a wrapper's parameters to the arguments it is immediately called with.
 *
 * These files are one expression: a function literal applied straight away to
 * a fixed argument list that carries the dispatcher's seed table and its memo
 * table.  Without those bindings every next-state expression reads an unknown
 * name and nothing resolves, so this is what makes the dispatcher analysable
 * at all.
 *
 *     return (function(w, N, ..., b, v) ... end)(type, '#', ..., {}, {24046, ...})
 *
 * Arguments that are library values rather than constants simply stay unknown.
 */
export function bindImmediateCallArguments(
  chunk: LuauNode,
): ReadonlyMap<string, LuaValue> {
  const bindings = new Map<string, LuaValue>();

  const unwrap = (node: LuauNode | undefined): LuauNode | undefined => {
    let current = node;
    while (current?.type === "ParenthesisExpression") {
      current = current.expression as LuauNode | undefined;
    }
    return current;
  };

  const walk = (node: unknown): void => {
    if (node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item);
      return;
    }
    const record = node as LuauNode;
    if (record.type === "CallExpression") {
      const callee = unwrap(record.base as LuauNode | undefined);
      if (callee?.type === "FunctionDeclaration") {
        const parameters = (callee.parameters as LuauNode[] | undefined) ?? [];
        const args = (record.arguments as LuauNode[] | undefined) ?? [];
        parameters.forEach((parameter, index) => {
          if (parameter.type !== "Identifier") return;
          const argument = args[index];
          if (argument === undefined) return;
          const value = evaluateConstantExpression(argument, {
            variables: bindings,
          });
          if (value !== null) bindings.set(String(parameter.name), value);
        });
      }
    }
    for (const [key, value] of Object.entries(record)) {
      if (key === "loc" || key === "range") continue;
      walk(value);
    }
  };
  walk(chunk);
  return bindings;
}

function isInfiniteLoop(node: LuauNode): boolean {
  if (node.type === "WhileStatement") {
    const condition = node.condition as LuauNode | undefined;
    return condition?.type === "BooleanLiteral" && condition.value === true;
  }
  if (node.type === "RepeatStatement") {
    // `repeat ... until false` is the same shape.
    const condition = node.condition as LuauNode | undefined;
    return condition?.type === "BooleanLiteral" && condition.value === false;
  }
  return false;
}

/**
 * Pull the state comparisons out of a condition.
 *
 * Dispatchers test the state variable in several shapes: `W == 31`,
 * `W < 114 and W > 31`, or a bare `W ~= 20`.  Only equality against a constant
 * identifies a single state, which is the case worth recovering; anything else
 * is reported as unmatched.
 */
function equalityStates(
  condition: LuauNode,
  variable: string,
  scope: ReadonlyMap<string, LuaValue>,
): readonly number[] | null {
  if (condition.type === "BinaryExpression" && condition.operator === "==") {
    const left = condition.left as LuauNode;
    const right = condition.right as LuauNode;
    const named =
      left.type === "Identifier" && left.name === variable
        ? right
        : right.type === "Identifier" && right.name === variable
          ? left
          : null;
    if (named === null) return null;
    const value = asStateNumber(
      evaluateConstantExpression(named, { variables: scope }),
    );
    return value === null ? null : [value];
  }
  if (condition.type === "LogicalExpression" && condition.operator === "or") {
    const left = equalityStates(condition.left as LuauNode, variable, scope);
    const right = equalityStates(condition.right as LuauNode, variable, scope);
    if (left === null || right === null) return null;
    return [...left, ...right];
  }
  return null;
}

/** Find assignments to the state variable inside a block, at any depth. */
function stateAssignments(
  body: readonly LuauNode[],
  variable: string,
): readonly LuauNode[] {
  const found: LuauNode[] = [];
  const walk = (node: unknown): void => {
    if (node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item);
      return;
    }
    const record = node as LuauNode;
    if (record.type === "AssignmentStatement") {
      const targets = (record.variables as LuauNode[] | undefined) ?? [];
      const values = (record.init as LuauNode[] | undefined) ?? [];
      targets.forEach((target, index) => {
        if (target.type === "Identifier" && target.name === variable) {
          const value = values[index];
          if (value !== undefined) found.push(value);
        }
      });
    }
    for (const [key, value] of Object.entries(record)) {
      if (key === "loc" || key === "range") continue;
      walk(value);
    }
  };
  walk(body);
  return found;
}

function containsExit(body: readonly LuauNode[]): boolean {
  let exits = false;
  const walk = (node: unknown): void => {
    if (exits || node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item);
      return;
    }
    const record = node as LuauNode;
    if (record.type === "BreakStatement" || record.type === "ReturnStatement") {
      exits = true;
      return;
    }
    // A nested loop's own `break` does not leave the dispatcher.
    if (record.type === "WhileStatement" || record.type === "RepeatStatement" ||
        record.type === "ForNumericStatement" || record.type === "ForGenericStatement") {
      return;
    }
    for (const [key, value] of Object.entries(record)) {
      if (key === "loc" || key === "range") continue;
      walk(value);
    }
  };
  walk(body);
  return exits;
}

/** Flatten an if/elseif/else chain into (condition, body) pairs. */
function clausesOf(node: LuauNode): readonly LuauNode[] {
  if (node.type !== "IfStatement") return [];
  return (node.clauses as LuauNode[] | undefined) ?? [];
}

/**
 * Collect the dispatcher's states by walking its if-chain, descending through
 * nested chains that switch on the same variable.
 */
function collectStates(
  body: readonly LuauNode[],
  variable: string,
  scope: ReadonlyMap<string, LuaValue>,
  states: DispatcherState[],
  limit: number,
): void {
  for (const statement of body) {
    if (states.length >= limit) return;
    if (statement.type !== "IfStatement") continue;
    for (const clause of clausesOf(statement)) {
      const condition = clause.condition as LuauNode | undefined;
      const clauseBody = (clause.body as LuauNode[] | undefined) ?? [];
      if (condition === undefined) {
        // An `else` clause: it may hold a nested dispatch on the same variable.
        collectStates(clauseBody, variable, scope, states, limit);
        continue;
      }
      const matched = equalityStates(condition, variable, scope);
      if (matched === null) {
        collectStates(clauseBody, variable, scope, states, limit);
        continue;
      }
      const exits = containsExit(clauseBody);
      for (const value of matched) {
        /*
         * Run the block against a store rather than folding its assignments in
         * isolation.  These dispatchers memoize the next state, so the value
         * only exists after a slot has been written and read back, and the
         * state variable is known on entry: it is the value that selected this
         * block.
         */
        const store = new ValueStore(scope);
        store.set(variable, integer(BigInt(Math.trunc(value))));
        const outcome = executeStatements(clauseBody, store);
        const executed =
          outcome.kind === "completed" || outcome.kind === "returned" || outcome.kind === "broke"
            ? asStateNumber(store.get(variable))
            : null;

        const successors =
          executed !== null && executed !== value
            ? [executed]
            : stateAssignments(clauseBody, variable)
                .map((expression) =>
                  asStateNumber(
                    evaluateConstantExpression(expression, { variables: scope }),
                  ),
                )
                .filter((candidate): candidate is number => candidate !== null);

        states.push({ value, body: clauseBody, successors, exits });
      }
    }
  }
}

/** Names assigned anywhere inside a block. */
function assignedNames(body: readonly LuauNode[]): ReadonlySet<string> {
  const names = new Set<string>();
  const walk = (node: unknown): void => {
    if (node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item);
      return;
    }
    const record = node as LuauNode;
    if (record.type === "AssignmentStatement") {
      for (const target of (record.variables as LuauNode[] | undefined) ?? []) {
        if (target.type === "Identifier") names.add(String(target.name));
      }
    }
    if (record.type === "CompoundAssignmentStatement") {
      const target = record.variable as LuauNode | undefined;
      if (target?.type === "Identifier") names.add(String(target.name));
    }
    for (const [key, value] of Object.entries(record)) {
      if (key === "loc" || key === "range") continue;
      walk(value);
    }
  };
  walk(body);
  return names;
}

/**
 * Identify the variable a `while true` loop switches on.
 *
 * Being compared often is not enough: these wrappers alias constants to
 * parameters, so a name like `x` bound to 1 at the call site appears in more
 * comparisons than the real state variable does.  A state variable is one the
 * loop both compares *and* assigns - that is what makes it a state.
 */
function inferStateVariable(body: readonly LuauNode[]): string | null {
  const counts = new Map<string, number>();
  const walk = (node: unknown, depth: number): void => {
    if (depth > 24 || node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item, depth);
      return;
    }
    const record = node as LuauNode;
    if (record.type === "BinaryExpression" && record.operator === "==") {
      for (const side of [record.left, record.right] as LuauNode[]) {
        if (side?.type === "Identifier") {
          const name = String(side.name);
          counts.set(name, (counts.get(name) ?? 0) + 1);
        }
      }
    }
    for (const [key, value] of Object.entries(record)) {
      if (key === "loc" || key === "range") continue;
      walk(value, depth + 1);
    }
  };
  walk(body, 0);
  const assigned = assignedNames(body);
  let best: string | null = null;
  let bestCount = 1;
  for (const [name, count] of counts) {
    if (!assigned.has(name)) continue;
    if (count > bestCount) {
      best = name;
      bestCount = count;
    }
  }
  return best;
}

/**
 * Recover every dispatcher in a parsed chunk.
 *
 * A loop qualifies only when it is unconditional and its body switches a
 * single variable against constants at least twice; anything looser would
 * misread an ordinary loop as a dispatcher.
 */
export function findFlattenedDispatchers(
  chunk: LuauNode,
  options: UnflattenOptions = {},
): readonly FlattenedDispatcher[] {
  // Seed from the wrapper's own call arguments unless the caller supplied a
  // scope; that is where the seed and memo tables come from.
  const scope = options.scope ?? bindImmediateCallArguments(chunk);
  const limit = options.maxStates ?? DEFAULT_MAX_STATES;
  const found: FlattenedDispatcher[] = [];

  const walk = (node: unknown): void => {
    if (node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item);
      return;
    }
    const record = node as LuauNode;
    if (isInfiniteLoop(record)) {
      const body = (record.body as LuauNode[] | undefined) ?? [];
      const variable = inferStateVariable(body);
      if (variable !== null) {
        const states: DispatcherState[] = [];
        collectStates(body, variable, scope, states, limit);
        if (states.length >= 2) {
          const unresolved = states
            .filter((state) => state.successors.length === 0 && !state.exits)
            .map((state) => state.value);
          found.push({
            stateVariable: variable,
            entryState: null,
            states,
            unresolvedStates: unresolved,
            loop: record,
          });
        }
      }
    }
    for (const [key, value] of Object.entries(record)) {
      if (key === "loc" || key === "range") continue;
      walk(value);
    }
  };
  walk(chunk);
  return found;
}

export interface DispatcherSummary {
  readonly dispatchers: number;
  readonly states: number;
  readonly resolvedEdges: number;
  readonly unresolvedStates: number;
  /** Share of states whose successor or exit was proven. */
  readonly resolutionRatio: number;
}

export function summarizeDispatchers(
  dispatchers: readonly FlattenedDispatcher[],
): DispatcherSummary {
  let states = 0;
  let resolvedEdges = 0;
  let unresolved = 0;
  for (const dispatcher of dispatchers) {
    states += dispatcher.states.length;
    for (const state of dispatcher.states) {
      resolvedEdges += state.successors.length;
      if (state.successors.length === 0 && !state.exits) unresolved += 1;
    }
  }
  return {
    dispatchers: dispatchers.length,
    states,
    resolvedEdges,
    unresolvedStates: unresolved,
    resolutionRatio: states === 0 ? 0 : (states - unresolved) / states,
  };
}

export interface DispatcherWalk {
  /** States in the order control actually reaches them. */
  readonly order: readonly number[];
  /** Why the walk stopped. */
  readonly stopped: "exit" | "unknown-state" | "missing-state" | "revisit" | "limit";
  /** Edges proven by walking, as `from -> to`. */
  readonly edges: readonly (readonly [number, number])[];
}

/**
 * Walk a dispatcher from an entry state, carrying one store across every
 * block.
 *
 * Resolving states independently cannot work: the next-state value is memoized
 * into a table that earlier states populate, so a block read in isolation sees
 * an empty slot. Threading a single store through the walk reproduces the
 * order the dispatcher itself would take, which is what turns the state
 * machine back into a sequence.
 *
 * The walk is bounded and stops rather than guessing whenever the next state
 * cannot be proven.
 */
export function walkDispatcher(
  dispatcher: FlattenedDispatcher,
  entryState: number,
  scope: ReadonlyMap<string, LuaValue>,
  maxSteps = 4_096,
): DispatcherWalk {
  const byValue = new Map<number, DispatcherState>();
  for (const state of dispatcher.states) {
    if (!byValue.has(state.value)) byValue.set(state.value, state);
  }

  const store = new ValueStore(scope);
  const order: number[] = [];
  const edges: (readonly [number, number])[] = [];
  const seen = new Set<number>();
  let current = entryState;

  for (let step = 0; step < maxSteps; step += 1) {
    const state = byValue.get(current);
    if (state === undefined) {
      return { order, stopped: "missing-state", edges };
    }
    if (seen.has(current)) {
      // A revisit means a real loop in the state machine; the sequence up to
      // here is still proven, so stop rather than unrolling forever.
      return { order, stopped: "revisit", edges };
    }
    seen.add(current);
    order.push(current);

    store.set(dispatcher.stateVariable, integer(BigInt(Math.trunc(current))));
    const outcome = executeStatements(state.body, store);
    if (outcome.kind === "returned" || outcome.kind === "broke" || state.exits) {
      return { order, stopped: "exit", edges };
    }
    if (outcome.kind === "limit" || outcome.kind === "unknown") {
      return { order, stopped: "limit", edges };
    }
    const next = asStateNumber(store.get(dispatcher.stateVariable));
    if (next === null) return { order, stopped: "unknown-state", edges };
    edges.push([current, next]);
    current = next;
  }
  return { order, stopped: "limit", edges };
}

/**
 * Entry states worth trying: constants the state variable is assigned outside
 * the dispatcher loop, plus every state, so a walk can still be attempted when
 * the initial assignment is not a plain constant.
 */
export function candidateEntryStates(
  chunk: LuauNode,
  dispatcher: FlattenedDispatcher,
  scope: ReadonlyMap<string, LuaValue>,
): readonly number[] {
  const candidates: number[] = [];
  const walk = (node: unknown): void => {
    if (node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item);
      return;
    }
    const record = node as LuauNode;
    if (record.type === "LocalStatement" || record.type === "AssignmentStatement") {
      const targets = (record.variables as LuauNode[] | undefined) ?? [];
      const values = ((record.init as LuauNode[] | undefined) ?? []);
      targets.forEach((target, index) => {
        if (target.type !== "Identifier") return;
        if (target.name !== dispatcher.stateVariable) return;
        const value = values[index];
        if (value === undefined) return;
        const resolved = asStateNumber(
          evaluateConstantExpression(value, { variables: scope }),
        );
        if (resolved !== null) candidates.push(resolved);
      });
    }
    for (const [key, value] of Object.entries(record)) {
      if (key === "loc" || key === "range") continue;
      walk(value);
    }
  };
  walk(chunk);
  const known = new Set(dispatcher.states.map((state) => state.value));
  const ordered = candidates.filter((value) => known.has(value));
  for (const state of dispatcher.states) ordered.push(state.value);
  return [...new Set(ordered)];
}
