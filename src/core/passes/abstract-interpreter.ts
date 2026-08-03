/**
 * Bounded abstract interpreter over our own Lua AST.
 *
 * `const-eval` folds a single expression, which is not enough for a flattened
 * dispatcher: its next state is usually memoized, so the value only appears
 * after a store has been written and read back.
 *
 *     if not b[0x4511] then
 *       b[0x4511] = -8432766656861699982 + (((v[6] + v[9] <= v[5] and ...)))
 *       W = b[0x4511]
 *     else
 *       W = b[0x4511]
 *     end
 *
 * Executing the block against a store resolves that; folding the expression
 * alone never can.  This walks statements in order over a value store, taking
 * a branch only when its condition is decidable and otherwise invalidating
 * whatever the branch could have written.
 *
 * It is still static: it interprets our AST through `const-eval`'s value model
 * and never hands anything to a Lua runtime.  Calls, varargs, and unknown
 * names invalidate rather than being simulated.
 *
 * Tables are updated functionally and rebound to their variable, so two names
 * bound to the same table are not modelled as aliases.  These dispatchers use
 * a single local for their memo, which this covers; anything else must be
 * treated as unknown.
 */

import {
  evaluateConstantExpression,
  isTruthy,
  type LuaValue,
} from "./const-eval";
import type { LuauNode } from "../source/luau-parser";

/** Result of running a statement list. */
export type ExecutionOutcome =
  | { readonly kind: "completed" }
  | { readonly kind: "returned" }
  | { readonly kind: "broke" }
  /** Hit something it could not model; the store is no longer trustworthy. */
  | { readonly kind: "unknown"; readonly reason: string }
  | { readonly kind: "limit" };

export interface InterpreterOptions {
  /** Statements executed before giving up. */
  readonly maxSteps?: number;
  /** Iterations of any single loop before giving up on it. */
  readonly maxLoopIterations?: number;
}

const DEFAULT_MAX_STEPS = 20_000;
const DEFAULT_MAX_LOOP_ITERATIONS = 256;

/** A mutable binding set; `null` marks a name whose value is not known. */
export class ValueStore {
  private readonly values = new Map<string, LuaValue | null>();

  constructor(initial?: ReadonlyMap<string, LuaValue>) {
    if (initial !== undefined) {
      for (const [name, value] of initial) this.values.set(name, value);
    }
  }

  get(name: string): LuaValue | null {
    return this.values.get(name) ?? null;
  }

  set(name: string, value: LuaValue | null): void {
    this.values.set(name, value);
  }

  has(name: string): boolean {
    return this.values.has(name);
  }

  /** Bindings that are currently known, for use as a const-eval scope. */
  scope(): ReadonlyMap<string, LuaValue> {
    const known = new Map<string, LuaValue>();
    for (const [name, value] of this.values) {
      if (value !== null) known.set(name, value);
    }
    return known;
  }

  clone(): ValueStore {
    const copy = new ValueStore();
    for (const [name, value] of this.values) copy.set(name, value);
    return copy;
  }

  /** Keep only bindings both stores agree on; the rest become unknown. */
  mergeWith(other: ValueStore): void {
    for (const [name, value] of this.values) {
      const theirs = other.values.get(name) ?? null;
      if (value === null || theirs === null || !sameValue(value, theirs)) {
        this.values.set(name, null);
      }
    }
    for (const name of other.values.keys()) {
      if (!this.values.has(name)) this.values.set(name, null);
    }
  }
}

function sameValue(left: LuaValue, right: LuaValue): boolean {
  if (left.kind !== right.kind) return false;
  switch (left.kind) {
    case "nil":
      return true;
    case "boolean":
      return left.value === (right as typeof left).value;
    case "integer":
      return left.value === (right as typeof left).value;
    case "float":
      return Object.is(left.value, (right as typeof left).value);
    case "string":
      return left.value === (right as typeof left).value;
    case "table": {
      const other = right as typeof left;
      if (left.entries.size !== other.entries.size) return false;
      for (const [key, value] of left.entries) {
        const theirs = other.entries.get(key);
        if (theirs === undefined || !sameValue(value, theirs)) return false;
      }
      return true;
    }
  }
}

/** Canonical table key, matching const-eval's addressing. */
function tableKey(value: LuaValue): string | null {
  switch (value.kind) {
    case "integer":
      return `n:${value.value.toString()}`;
    case "float":
      if (!Number.isFinite(value.value)) return null;
      return Number.isInteger(value.value)
        ? `n:${BigInt(value.value).toString()}`
        : `f:${value.value}`;
    case "string":
      return `s:${value.value}`;
    case "boolean":
      return `b:${value.value}`;
    default:
      return null;
  }
}

function withEntry(table: LuaValue, key: string, value: LuaValue): LuaValue {
  if (table.kind !== "table") return table;
  const entries = new Map(table.entries);
  entries.set(key, value);
  return { kind: "table", entries };
}

class Interpreter {
  private steps = 0;

  constructor(
    private readonly store: ValueStore,
    private readonly maxSteps: number,
    private readonly maxLoopIterations: number,
  ) {}

  run(statements: readonly LuauNode[]): ExecutionOutcome {
    for (const statement of statements) {
      this.steps += 1;
      if (this.steps > this.maxSteps) return { kind: "limit" };
      const outcome = this.statement(statement);
      if (outcome.kind !== "completed") return outcome;
    }
    return { kind: "completed" };
  }

  private evaluate(node: LuauNode | undefined): LuaValue | null {
    if (node === undefined) return null;
    return evaluateConstantExpression(node, { variables: this.store.scope() });
  }

  private statement(node: LuauNode): ExecutionOutcome {
    switch (node.type) {
      case "LocalStatement":
        return this.local(node);
      case "AssignmentStatement":
        return this.assignment(node);
      case "CompoundAssignmentStatement":
        return this.compound(node);
      case "IfStatement":
        return this.ifStatement(node);
      case "DoStatement":
        return this.run((node.body as LuauNode[]) ?? []);
      case "WhileStatement":
        return this.whileStatement(node);
      case "RepeatStatement":
        return this.repeatStatement(node);
      case "ReturnStatement":
        return { kind: "returned" };
      case "BreakStatement":
        return { kind: "broke" };
      case "LabelStatement":
      case "TypeAliasStatement":
        return { kind: "completed" };
      case "CallStatement":
        // A call can do anything, including writing through upvalues.
        this.invalidateAll();
        return { kind: "completed" };
      default:
        return { kind: "unknown", reason: `unsupported statement ${String(node.type)}` };
    }
  }

  private invalidateAll(): void {
    for (const name of [...this.store.scope().keys()]) this.store.set(name, null);
  }

  private local(node: LuauNode): ExecutionOutcome {
    const variables = (node.variables as LuauNode[] | undefined) ?? [];
    const init = (node.init as LuauNode[] | undefined) ?? [];
    variables.forEach((variable, index) => {
      if (variable.type !== "Identifier") return;
      const value = index < init.length ? this.evaluate(init[index]) : null;
      // `local a, b = 1` leaves b nil, which is a known value.
      this.store.set(
        String(variable.name),
        init.length === 0 ? { kind: "nil" } : value,
      );
    });
    return { kind: "completed" };
  }

  private assignment(node: LuauNode): ExecutionOutcome {
    const targets = (node.variables as LuauNode[] | undefined) ?? [];
    const values = (node.init as LuauNode[] | undefined) ?? [];
    // Evaluate every right-hand side before assigning, as Lua does.
    const evaluated = values.map((value) => this.evaluate(value));
    targets.forEach((target, index) => {
      this.assignTo(target, evaluated[index] ?? null);
    });
    return { kind: "completed" };
  }

  private compound(node: LuauNode): ExecutionOutcome {
    // `x += e` is `x = x + e`; without folding the operator, the target is
    // simply no longer known.
    this.assignTo(node.variable as LuauNode, null);
    return { kind: "completed" };
  }

  private assignTo(target: LuauNode, value: LuaValue | null): void {
    if (target.type === "Identifier") {
      this.store.set(String(target.name), value);
      return;
    }
    if (target.type === "IndexExpression" || target.type === "MemberExpression") {
      const base = target.base as LuauNode;
      if (base.type !== "Identifier") return;
      const name = String(base.name);
      const table = this.store.get(name);
      const key =
        target.type === "MemberExpression"
          ? ({ kind: "string", value: String((target.identifier as LuauNode).name) } as LuaValue)
          : this.evaluate(target.index as LuauNode);
      if (table === null || table.kind !== "table" || key === null || value === null) {
        // An unknown slot poisons the whole table: later reads cannot be
        // distinguished from the slot that was just written.
        this.store.set(name, null);
        return;
      }
      const canonical = tableKey(key);
      if (canonical === null) {
        this.store.set(name, null);
        return;
      }
      this.store.set(name, withEntry(table, canonical, value));
      return;
    }
    // Anything else is an assignment target this model does not follow.
  }

  private ifStatement(node: LuauNode): ExecutionOutcome {
    const clauses = (node.clauses as LuauNode[] | undefined) ?? [];
    for (const clause of clauses) {
      const condition = clause.condition as LuauNode | undefined;
      const body = (clause.body as LuauNode[] | undefined) ?? [];
      if (condition === undefined) {
        // Reached the `else`.
        return this.run(body);
      }
      const value = this.evaluate(condition);
      if (value === null) {
        // Undecidable: every branch might run, so nothing they touch survives.
        return this.invalidateBranches(clauses);
      }
      if (isTruthy(value)) return this.run(body);
    }
    return { kind: "completed" };
  }

  /** Forget everything an undecidable if-chain could have written. */
  private invalidateBranches(clauses: readonly LuauNode[]): ExecutionOutcome {
    const written = new Set<string>();
    const walk = (node: unknown): void => {
      if (node === null || typeof node !== "object") return;
      if (Array.isArray(node)) {
        for (const item of node) walk(item);
        return;
      }
      const record = node as LuauNode;
      if (record.type === "AssignmentStatement" || record.type === "LocalStatement") {
        const targets =
          (record.variables as LuauNode[] | undefined) ?? [];
        for (const target of targets) {
          const base =
            target.type === "Identifier"
              ? target
              : (target.base as LuauNode | undefined);
          if (base?.type === "Identifier") written.add(String(base.name));
        }
      }
      if (record.type === "CompoundAssignmentStatement") {
        const target = record.variable as LuauNode | undefined;
        const base =
          target?.type === "Identifier" ? target : (target?.base as LuauNode | undefined);
        if (base?.type === "Identifier") written.add(String(base.name));
      }
      if (record.type === "CallStatement") written.add("*");
      for (const [key, value] of Object.entries(record)) {
        if (key === "loc" || key === "range") continue;
        walk(value);
      }
    };
    walk(clauses);
    if (written.has("*")) {
      this.invalidateAll();
      return { kind: "completed" };
    }
    for (const name of written) this.store.set(name, null);
    return { kind: "completed" };
  }

  private whileStatement(node: LuauNode): ExecutionOutcome {
    const condition = node.condition as LuauNode;
    const body = (node.body as LuauNode[] | undefined) ?? [];
    for (let iteration = 0; iteration < this.maxLoopIterations; iteration += 1) {
      const value = this.evaluate(condition);
      if (value === null) {
        return this.invalidateBranches([{ ...node, body } as LuauNode]);
      }
      if (!isTruthy(value)) return { kind: "completed" };
      const outcome = this.run(body);
      if (outcome.kind === "broke") return { kind: "completed" };
      if (outcome.kind !== "completed") return outcome;
    }
    return { kind: "limit" };
  }

  private repeatStatement(node: LuauNode): ExecutionOutcome {
    const condition = node.condition as LuauNode;
    const body = (node.body as LuauNode[] | undefined) ?? [];
    for (let iteration = 0; iteration < this.maxLoopIterations; iteration += 1) {
      const outcome = this.run(body);
      if (outcome.kind === "broke") return { kind: "completed" };
      if (outcome.kind !== "completed") return outcome;
      const value = this.evaluate(condition);
      if (value === null) {
        return this.invalidateBranches([{ ...node, body } as LuauNode]);
      }
      if (isTruthy(value)) return { kind: "completed" };
    }
    return { kind: "limit" };
  }
}

/**
 * Execute a statement list against a store, returning how it finished.
 * The store is mutated in place, so callers pass a clone when they need the
 * original preserved.
 */
export function executeStatements(
  statements: readonly LuauNode[],
  store: ValueStore,
  options: InterpreterOptions = {},
): ExecutionOutcome {
  return new Interpreter(
    store,
    options.maxSteps ?? DEFAULT_MAX_STEPS,
    options.maxLoopIterations ?? DEFAULT_MAX_LOOP_ITERATIONS,
  ).run(statements);
}
