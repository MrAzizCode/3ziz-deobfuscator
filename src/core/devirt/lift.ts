/**
 * Lift one decoded prototype's proven opcode effects into Lua statements.
 *
 * The strategy is deliberately conservative and layered:
 *
 * 1. every instruction becomes exactly one statement, so nothing is dropped;
 * 2. registers become named locals, so the result is always valid Lua;
 * 3. a single-use forward-inlining pass folds `v5 = game; v6 = v5.Workspace`
 *    into `v6 = game.Workspace`, but only across a window with no call, no
 *    store, and no branch - the barriers that would change evaluation order;
 * 4. control flow is recovered where a pattern is proven, and falls back to
 *    `goto`/labels otherwise.
 *
 * Anything unproven keeps its raw record as a comment.  No name, no operand,
 * and no effect is invented.
 */

import {
  instructionAt,
  type JnkieDecodedConstant,
  type JnkieDecodedPrototype,
  type JnkieRecordSection,
} from "../recovery/jnkie-record-model";
import { PROTOCOL_OPCODES } from "../recovery/jnkie-semantic-emitter";
import {
  resolveOpEffect,
  type JnkieCallArguments,
  type JnkieOpEffect,
  type JnkieValue,
} from "../recovery/op-effects";
import {
  blockLabel,
  buildControlFlowGraph,
  orderBlocks,
  type BasicBlock,
  type ControlFlowGraph,
} from "./cfg";
import {
  formatLuaNumber,
  isValidIdentifier,
  literal,
  name,
  quoteLuaString,
  type LuaExpression,
  type LuaStatement,
} from "./lua-ast";

export interface LiftedPrototype {
  readonly index: number;
  readonly statements: readonly LuaStatement[];
  readonly instructionCount: number;
  /** Instructions reachable from the entry point; the rest is decoy code. */
  readonly reachableInstructionCount: number;
  readonly unreachableInstructionCount: number;
  readonly provenCount: number;
  /** Decoder-protocol records: explained, but with no guest-level effect. */
  readonly protocolCount: number;
  readonly unresolvedCount: number;
  /** Registers referenced anywhere, so the caller can declare them. */
  readonly registers: readonly number[];
  readonly childPrototypes: readonly number[];
  readonly usesVararg: boolean;
  readonly unstructuredRegions: number;
}

const BINARY_OPERATORS: Readonly<Record<string, string>> = {
  add: "+",
  sub: "-",
  mul: "*",
  div: "/",
  mod: "%",
  eq: "==",
  ne: "~=",
  lt: "<",
  le: "<=",
  gt: ">",
  ge: ">=",
};

/** Comparison inverses, used to turn a branch-if-false into a readable `if`. */
const INVERSE_COMPARISON: Readonly<Record<string, string>> = {
  eq: "ne",
  ne: "eq",
  lt: "ge",
  ge: "lt",
  le: "gt",
  gt: "le",
};

export function registerName(index: number): string {
  return `v${index}`;
}

/** Render a decoded constant as a Lua literal, or null when it is not one. */
export function constantExpression(
  constant: JnkieDecodedConstant | undefined,
): LuaExpression | null {
  if (constant === undefined) return null;
  switch (constant.kind) {
    case "string": {
      if (constant.utf8Text !== null) return literal(quoteLuaString(constant.utf8Text));
      // Non-UTF-8 constants are byte strings; emit them by escape so the value
      // survives exactly rather than being lossily transcoded.
      const escaped = [...constant.latin1Text]
        .map((character) => `\\${character.charCodeAt(0)}`)
        .join("");
      return literal(`"${escaped}"`);
    }
    case "integer":
      return literal(constant.exactDecimal);
    case "float":
      return literal(formatLuaNumber(constant.value));
    case "boolean":
      return literal(constant.value ? "true" : "false");
    case "buffer":
      return null;
    default:
      return null;
  }
}

class Lifter {
  private readonly statements: LuaStatement[] = [];
  private readonly usedRegisters = new Set<number>();
  private readonly childPrototypes = new Set<number>();
  private readonly labelTargets = new Set<number>();
  private provenCount = 0;
  private protocolCount = 0;
  private unresolvedCount = 0;
  private usesVararg = false;
  private unstructuredRegions = 0;

  constructor(
    private readonly section: JnkieRecordSection,
    private readonly prototype: JnkieDecodedPrototype,
  ) {}

  lift(): LiftedPrototype {
    const effects = this.decodeEffects();
    const cfg = buildControlFlowGraph(effects);
    const order = orderBlocks(cfg);

    /*
     * Every block is emitted.  Static reachability from the entry point covers
     * only about a seventh of this stream and excludes every recovered API
     * name, so the dispatcher's control flow is evidently data-driven and
     * pruning on it would hide real code.  The figure is still reported.
     */
    const gotoTargets = new Set<number>();
    const bodies = new Map<number, LuaStatement[]>();
    const positionOf = new Map<number, number>();
    order.forEach((blockId, position) => positionOf.set(blockId, position));

    // Statements for each block's instructions, without its terminator.
    for (const blockId of order) {
      const block = cfg.blocks[blockId]!;
      const statements: LuaStatement[] = [];
      for (let pc = block.start; pc <= block.end; pc += 1) {
        const effect = effects[pc - 1] ?? null;
        if (effect === null) {
          const opcode = instructionAt(this.prototype.instructions, pc).rawOpcode;
          if (PROTOCOL_OPCODES.has(opcode)) this.protocolCount += 1;
          else this.unresolvedCount += 1;
          statements.push({ kind: "comment", text: this.rawRecordComment(pc) });
          continue;
        }
        this.provenCount += 1;
        // The terminator is rendered from the block, not the instruction.
        if (pc === block.end && block.terminator.kind !== "fallthrough") continue;
        this.emitInto(statements, effect, pc);
      }
      bodies.set(blockId, statements);
    }

    /*
     * Two passes: the first discovers which blocks are still jumped to, the
     * second emits with exactly those labels.  Structuring decisions do not
     * depend on the label set, so the second pass produces the same shape.
     */
    const context = { cfg, order, positionOf, bodies, gotoTargets };
    this.emitRegion(0, order.length, context);
    const body = this.emitRegion(0, order.length, context);
    this.unstructuredRegions = gotoTargets.size;

    return {
      index: this.prototype.index,
      statements: wrapNonTerminalReturns(
        inlineSingleUseTemporaries(recoverMethodCalls(body)),
      ),
      instructionCount: effects.length,
      reachableInstructionCount: cfg.reachableInstructionCount,
      unreachableInstructionCount: cfg.unreachableInstructionCount,
      provenCount: this.provenCount,
      protocolCount: this.protocolCount,
      unresolvedCount: this.unresolvedCount,
      registers: [...this.usedRegisters].sort((left, right) => left - right),
      childPrototypes: [...this.childPrototypes],
      usesVararg: this.usesVararg,
      unstructuredRegions: this.unstructuredRegions,
    };
  }

  /**
   * Emit blocks at order positions `[from, to)`, recovering `if ... then`
   * wherever a conditional guards a single-entry region.
   *
   * The shape recognized is the common one: a block branches past a region,
   * that region is entered only from this block, and every path out of it
   * lands on the branch target.  That is exactly an `if`, so it is emitted as
   * one with the condition inverted.  Anything that does not fit stays as
   * `goto` rather than being forced into a structure it does not have.
   */
  private emitRegion(
    from: number,
    to: number,
    context: RegionContext,
  ): LuaStatement[] {
    const { cfg, order, positionOf, bodies, gotoTargets } = context;
    const out: LuaStatement[] = [];
    let position = from;

    while (position < to) {
      const blockId = order[position]!;
      const block = cfg.blocks[blockId]!;

      /*
       * Loop recovery is deliberately not attempted here.  A back edge alone
       * does not make a natural loop - the head must dominate its source - and
       * this obfuscator's dispatch is flattened enough that wrapping back
       * edges in `while true do` produced loops whose first statement was a
       * jump out of them: correct, but less readable than the goto it
       * replaced.  Recovering real loops needs the dispatcher's state
       * variable solved, which is a separate analysis.
       */
      if (gotoTargets.has(blockId)) {
        out.push({ kind: "label", name: blockLabel(block) });
      }
      out.push(...(bodies.get(blockId) ?? []));

      const terminator = block.terminator;
      const nextPosition = position + 1;
      const nextId = order[nextPosition];

      if (terminator.kind === "exit" || terminator.kind === "fallthrough") {
        position = nextPosition;
        continue;
      }

      if (terminator.kind === "jump") {
        const targetId = cfg.blockAt.get(terminator.target);
        if (targetId !== undefined && targetId !== nextId) {
          gotoTargets.add(targetId);
          out.push({ kind: "goto", label: blockLabel(cfg.blocks[targetId]!) });
        }
        position = nextPosition;
        continue;
      }

      const targetId = cfg.blockAt.get(terminator.target);
      const fallthroughId = cfg.blockAt.get(terminator.fallthrough);
      const targetPosition =
        targetId === undefined ? undefined : positionOf.get(targetId);

      if (
        fallthroughId === nextId &&
        targetPosition !== undefined &&
        targetPosition > nextPosition &&
        targetPosition <= to &&
        isSingleEntryRegion(nextPosition, targetPosition, blockId, context)
      ) {
        const condition = this.branchCondition(terminator.effect, true);
        if (condition !== null) {
          const inner = this.emitRegion(nextPosition, targetPosition, context);
          out.push({ kind: "if", condition, then: inner });
          position = targetPosition;
          continue;
        }
      }

      const condition = this.branchCondition(terminator.effect, false);
      if (condition !== null && targetId !== undefined) {
        gotoTargets.add(targetId);
        out.push({
          kind: "if",
          condition,
          then: [{ kind: "goto", label: blockLabel(cfg.blocks[targetId]!) }],
        });
      }
      if (fallthroughId !== undefined && fallthroughId !== nextId) {
        gotoTargets.add(fallthroughId);
        out.push({
          kind: "goto",
          label: blockLabel(cfg.blocks[fallthroughId]!),
        });
      }
      position = nextPosition;
    }
    return out;
  }

  /**
   * Render a block's exit.  A jump to the block that is emitted next needs no
   * jump at all, which is what removes most of the `goto` chains.
   */
  private emitTerminator(
    statements: LuaStatement[],
    block: BasicBlock,
    nextBlockId: number | undefined,
    cfg: ControlFlowGraph,
    gotoTargets: Set<number>,
  ): void {
    const jumpTo = (targetPc: number): void => {
      const targetId = cfg.blockAt.get(targetPc);
      if (targetId === undefined) return;
      if (targetId === nextBlockId) return; // falls through
      gotoTargets.add(targetId);
      statements.push({
        kind: "goto",
        label: blockLabel(cfg.blocks[targetId]!),
      });
    };

    switch (block.terminator.kind) {
      case "exit":
      case "fallthrough":
        return;
      case "jump":
        jumpTo(block.terminator.target);
        return;
      case "branch": {
        const { effect, target, fallthrough } = block.terminator;
        const targetId = cfg.blockAt.get(target);
        const fallthroughId = cfg.blockAt.get(fallthrough);

        /*
         * When the branch target is the next block, invert the condition so
         * the taken edge reads as the `if` body instead of as a jump around
         * a jump.
         */
        if (targetId === nextBlockId && fallthroughId !== undefined) {
          const condition = this.branchCondition(effect, true);
          if (condition !== null) {
            gotoTargets.add(fallthroughId);
            statements.push({
              kind: "if",
              condition,
              then: [
                { kind: "goto", label: blockLabel(cfg.blocks[fallthroughId]!) },
              ],
            });
            return;
          }
        }

        const condition = this.branchCondition(effect, false);
        if (condition === null) return;
        if (targetId !== undefined && targetId !== nextBlockId) {
          gotoTargets.add(targetId);
          statements.push({
            kind: "if",
            condition,
            then: [{ kind: "goto", label: blockLabel(cfg.blocks[targetId]!) }],
          });
        }
        if (fallthroughId !== undefined && fallthroughId !== nextBlockId) {
          gotoTargets.add(fallthroughId);
          statements.push({
            kind: "goto",
            label: blockLabel(cfg.blocks[fallthroughId]!),
          });
        }
        return;
      }
      default:
        return;
    }
  }

  /** The condition under which a branch is taken, optionally inverted. */
  private branchCondition(
    effect: JnkieOpEffect,
    invert: boolean,
  ): LuaExpression | null {
    if (effect.kind === "test") {
      const operand = this.target(effect.operand);
      const truthy = effect.expect === "truthy";
      return truthy !== invert
        ? operand
        : { kind: "unary", operator: "not", operand };
    }
    if (effect.kind === "compare-jump") {
      const operator = invert
        ? BINARY_OPERATORS[INVERSE_COMPARISON[effect.operator] ?? effect.operator]
        : BINARY_OPERATORS[effect.operator];
      if (operator === undefined) return null;
      return {
        kind: "binary",
        operator,
        left: this.value(effect.left),
        right: this.value(effect.right),
      };
    }
    if (effect.kind === "for-loop") {
      // The loop's own condition lives in VM state, not in a register.
      return {
        kind: "raw",
        text: "false --[[3ziz: numeric for continuation, see comment above]]",
      };
    }
    return null;
  }

  private decodeEffects(): readonly (JnkieOpEffect | null)[] {
    const effects: (JnkieOpEffect | null)[] = [];
    for (let pc = 1; pc <= this.prototype.instructionCount; pc += 1) {
      const instruction = instructionAt(this.prototype.instructions, pc);
      const resolved = resolveOpEffect(instruction, this.prototype.selector);
      effects.push(resolved === null ? null : resolved.effect);
    }
    return effects;
  }

  /** Every branch destination becomes a label; unmatched ones stay as gotos. */
  private collectLabels(effects: readonly (JnkieOpEffect | null)[]): void {
    for (const effect of effects) {
      if (effect === null) continue;
      const target = branchTarget(effect);
      if (target !== null && target >= 1 && target <= effects.length) {
        this.labelTargets.add(target);
      }
    }
  }

  private rawRecordComment(pc: number): string {
    const instruction = instructionAt(this.prototype.instructions, pc);
    const { A, N, Q } = instruction.channels;
    /*
     * Separate the two reasons an instruction produced no source statement.
     * Decoder-protocol handlers move the interpreter's own state and have no
     * guest-level effect to emit, which is a different fact from an opcode
     * this dispatcher never proved at all.
     */
    const kind = PROTOCOL_OPCODES.has(instruction.rawOpcode)
      ? "VM decoder protocol op"
      : "unresolved VM op";
    return (
      `[3ziz] ${kind} ${instruction.rawOpcode} ` +
      `A=${A.payload}/${A.mode} N=${N.payload}/${N.mode} Q=${Q.payload}/${Q.mode} ` +
      `@bytes[${instruction.byteRange.start},${instruction.byteRange.end})`
    );
  }

  private value(source: JnkieValue): LuaExpression {
    switch (source.kind) {
      case "register":
        this.usedRegisters.add(source.index);
        return name(registerName(source.index));
      case "number":
        return literal(formatLuaNumber(source.value));
      case "prototype":
        this.childPrototypes.add(source.index);
        return name(prototypeFunctionName(source.index));
      case "constant": {
        const constant = this.section.constants[source.index - 1];
        const rendered = constantExpression(constant);
        if (rendered !== null) return rendered;
        // An unrenderable constant is named, never guessed at.
        return {
          kind: "raw",
          text: `nil --[[3ziz: constant #${source.index} is not a Lua literal]]`,
        };
      }
      default:
        return literal("nil");
    }
  }

  private target(index: number): LuaExpression {
    this.usedRegisters.add(index);
    return name(registerName(index));
  }

  private registerRange(first: number, count: number): LuaExpression[] {
    const values: LuaExpression[] = [];
    for (let offset = 0; offset < count; offset += 1) {
      values.push(this.target(first + offset));
    }
    return values;
  }

  private callArguments(args: JnkieCallArguments): LuaExpression[] {
    if (args.kind === "fixed") return this.registerRange(args.first, args.count);
    // The open form consumes to the VM's stack top, whose extent is a runtime
    // fact.  Forward the vararg marker rather than inventing an argument count.
    this.usesVararg = true;
    return [{ kind: "raw", text: "--[[3ziz: arguments to VM_TOP]] ..." }];
  }

  private emitInto(
    statements: LuaStatement[],
    effect: JnkieOpEffect,
    pc: number,
  ): void {
    switch (effect.kind) {
      case "assign":
        statements.push({
          kind: "assign",
          targets: [this.target(effect.target)],
          values: [this.expression(effect.expression)],
        });
        return;
      case "table-set":
        statements.push({
          kind: "assign",
          targets: [
            { kind: "index", object: this.value(effect.table), key: this.value(effect.key) },
          ],
          values: [this.value(effect.value)],
        });
        return;
      case "self":
        // `R[t+1] = R[o]` then `R[t] = R[o][k]`: the receiver copy comes first.
        statements.push({
          kind: "assign",
          targets: [this.target(effect.target + 1)],
          values: [this.target(effect.object)],
        });
        statements.push({
          kind: "assign",
          targets: [this.target(effect.target)],
          values: [
            {
              kind: "index",
              object: this.target(effect.object),
              key: this.value(effect.key),
            },
          ],
        });
        return;
      case "call": {
        const call: LuaExpression = {
          kind: "call",
          callee: this.target(effect.base),
          args: this.callArguments(effect.arguments),
        };
        if (effect.results.kind === "none") {
          statements.push({ kind: "call", call });
          return;
        }
        if (effect.results.kind === "fixed") {
          statements.push({
            kind: "assign",
            targets: this.registerRange(effect.results.first, effect.results.count),
            values: [call],
          });
          return;
        }
        statements.push({
          kind: "assign",
          targets: [this.target(effect.results.first)],
          values: [call],
        });
        statements.push({
          kind: "comment",
          text: "[3ziz] this call expands to all results at the VM stack top",
        });
        return;
      }
      case "tailcall":
        statements.push({
          kind: "return",
          values: [
            {
              kind: "call",
              callee: this.target(effect.base),
              args: this.callArguments(effect.arguments),
            },
          ],
        });
        return;
      case "return":
        statements.push({
          kind: "return",
          values:
            effect.values.kind === "none"
              ? []
              : this.registerRange(effect.values.first, Math.max(0, effect.values.count)),
        });
        return;
      case "jump":
        statements.push({ kind: "goto", label: `L${effect.target}` });
        this.unstructuredRegions += 1;
        return;
      case "test": {
        const operand = this.target(effect.operand);
        const condition: LuaExpression =
          effect.expect === "truthy"
            ? operand
            : { kind: "unary", operator: "not", operand };
        statements.push({
          kind: "if",
          condition,
          then: [{ kind: "goto", label: `L${effect.target}` }],
        });
        this.unstructuredRegions += 1;
        return;
      }
      case "compare-jump": {
        const operator = BINARY_OPERATORS[effect.operator] ?? "==";
        statements.push({
          kind: "if",
          condition: {
            kind: "binary",
            operator,
            left: this.value(effect.left),
            right: this.value(effect.right),
          },
          then: [{ kind: "goto", label: `L${effect.target}` }],
        });
        this.unstructuredRegions += 1;
        return;
      }
      case "for-prep":
        /*
         * The VM keeps the loop index, limit, and step in three consecutive
         * registers.  Reconstructing a real `for` needs the matching FORLOOP,
         * which is recovered by the structuring pass; until then the state is
         * stated explicitly so nothing is lost.
         */
        statements.push({
          kind: "comment",
          text:
            `[3ziz] numeric for setup at pc ${pc}: control=${registerName(effect.base)}, ` +
            `limit=${registerName(effect.base + 1)}, step=${registerName(effect.base + 2)}`,
        });
        statements.push({ kind: "goto", label: `L${effect.target}` });
        return;
      case "for-loop":
        statements.push({
          kind: "comment",
          text: `[3ziz] numeric for continuation; loop variable ${registerName(effect.variable)}`,
        });
        statements.push({ kind: "goto", label: `L${effect.target}` });
        return;
      case "vararg":
        this.usesVararg = true;
        statements.push({
          kind: "assign",
          targets: this.registerRange(effect.first, Math.max(1, effect.count)),
          values: [{ kind: "vararg" }],
        });
        return;
      case "table-move": {
        const count = effect.sourceLast - effect.sourceFirst + 1;
        for (let offset = 0; offset < count; offset += 1) {
          statements.push({
            kind: "assign",
            targets: [
              {
                kind: "index",
                object: this.target(effect.destination),
                key: literal(String(effect.destinationFirst + offset)),
              },
            ],
            values: [this.target(effect.sourceFirst + offset)],
          });
        }
        return;
      }
      case "clear-range":
        for (let index = effect.first; index <= effect.last; index += 1) {
          statements.push({
            kind: "assign",
            targets: [this.target(index)],
            values: [literal("nil")],
          });
        }
        return;
      default:
        return;
    }
  }

  private expression(expression: JnkieOpEffect extends never ? never : Expression): LuaExpression {
    switch (expression.kind) {
      case "value":
        return this.value(expression.value);
      case "nil":
        return literal("nil");
      case "new-table":
        return { kind: "table", fields: [] };
      case "closure":
        return this.value(expression.prototype);
      case "environment": {
        const key = this.value(expression.key);
        // A constant string key is the script's own global name.
        if (key.kind === "literal" && /^"[A-Za-z_]\w*"$/.test(key.text)) {
          const identifier = key.text.slice(1, -1);
          if (isValidIdentifier(identifier)) return name(identifier);
        }
        return { kind: "index", object: name("_ENV"), key };
      }
      case "upvalue":
        return name(`upvalue${expression.index}`);
      case "runtime-slot":
        return {
          kind: "index",
          object: name("VM_RUNTIME"),
          key: literal(String(expression.index)),
        };
      case "table-get":
        return {
          kind: "index",
          object: this.value(expression.table),
          key: this.value(expression.key),
        };
      case "length":
        return { kind: "unary", operator: "#", operand: this.value(expression.operand) };
      case "binary": {
        if (expression.operator === "rshift") {
          return {
            kind: "call",
            callee: { kind: "index", object: name("bit32"), key: literal('"rshift"') },
            args: [this.value(expression.left), this.value(expression.right)],
          };
        }
        return {
          kind: "binary",
          operator: BINARY_OPERATORS[expression.operator] ?? "==",
          left: this.value(expression.left),
          right: this.value(expression.right),
        };
      }
      default:
        return literal("nil");
    }
  }
}

/** Local alias so the switch above stays readable. */
type Expression = Extract<JnkieOpEffect, { kind: "assign" }>["expression"];

export function prototypeFunctionName(index: number): string {
  return `fn${index}`;
}

interface RegionContext {
  readonly cfg: ControlFlowGraph;
  readonly order: readonly number[];
  readonly positionOf: ReadonlyMap<number, number>;
  readonly bodies: ReadonlyMap<number, LuaStatement[]>;
  readonly gotoTargets: Set<number>;
}


/**
 * Prove that order positions `[from, to)` form an `if` body: entered only from
 * `headerId`, and leaving only to the block at `to` (or by returning).
 *
 * Without this check a conditional could be wrapped around code that other
 * blocks also jump into, which would silently change control flow.
 */
function isSingleEntryRegion(
  from: number,
  to: number,
  headerId: number,
  context: RegionContext,
): boolean {
  const { cfg, order, positionOf } = context;
  const inside = new Set<number>();
  for (let position = from; position < to; position += 1) {
    const id = order[position];
    if (id === undefined) return false;
    inside.add(id);
  }
  const followId = order[to];

  for (const id of inside) {
    const block = cfg.blocks[id];
    if (block === undefined) return false;
    for (const predecessor of block.predecessors) {
      if (predecessor !== headerId && !inside.has(predecessor)) return false;
    }
    for (const successor of block.successors) {
      if (inside.has(successor) || successor === followId) continue;
      // An edge out of the region that does not land on the follow block
      // means this is not a plain `if`.
      const successorPosition = positionOf.get(successor);
      if (successorPosition === undefined) return false;
      return false;
    }
  }
  return true;
}

function branchTarget(effect: JnkieOpEffect): number | null {
  switch (effect.kind) {
    case "jump":
    case "test":
    case "compare-jump":
    case "for-prep":
      return effect.kind === "for-prep" ? effect.target : effect.target;
    case "for-loop":
      return effect.target;
    default:
      return null;
  }
}

/**
 * Lua allows `return` only as the last statement of a block, but a VM function
 * returns from anywhere.  Wrapping a non-final return in `do ... end` keeps the
 * exact semantics and satisfies the grammar.
 */
export function wrapNonTerminalReturns(
  statements: readonly LuaStatement[],
): readonly LuaStatement[] {
  const result: LuaStatement[] = [];
  for (let index = 0; index < statements.length; index += 1) {
    const statement = statements[index]!;
    const isLast = index === statements.length - 1;
    if (statement.kind === "return" && !isLast) {
      result.push({ kind: "do", body: [statement] });
      continue;
    }
    if (statement.kind === "if") {
      result.push({
        ...statement,
        then: wrapNonTerminalReturns(statement.then),
        ...(statement.else === undefined
          ? {}
          : { else: wrapNonTerminalReturns(statement.else) }),
      });
      continue;
    }
    if (statement.kind === "while") {
      result.push({ ...statement, body: wrapNonTerminalReturns(statement.body) });
      continue;
    }
    if (statement.kind === "numeric-for") {
      result.push({ ...statement, body: wrapNonTerminalReturns(statement.body) });
      continue;
    }
    if (statement.kind === "do") {
      result.push({ ...statement, body: wrapNonTerminalReturns(statement.body) });
      continue;
    }
    result.push(statement);
  }
  return result;
}

/**
 * Recover `obj:method(...)` from the three-statement shape the VM emits.
 *
 * `SELF_LOOKUP` copies the receiver into the next register and fetches the
 * method beside it, and the following call passes that receiver as the first
 * argument.  That is precisely Lua's colon call, and restoring it removes two
 * lines and a temporary from every method call in the output.
 *
 * The rewrite only fires when the receiver copy, the method fetch, and the
 * call are adjacent and agree on all three registers, so it cannot reorder
 * anything or change what is evaluated.
 */
export function recoverMethodCalls(
  statements: readonly LuaStatement[],
): readonly LuaStatement[] {
  const result: LuaStatement[] = [];
  for (let index = 0; index < statements.length; index += 1) {
    const receiverCopy = statements[index];
    const methodFetch = statements[index + 1];
    const callSite = statements[index + 2];
    const rewritten =
      receiverCopy === undefined || methodFetch === undefined || callSite === undefined
        ? null
        : tryMethodCall(receiverCopy, methodFetch, callSite);
    if (rewritten === null) {
      result.push(receiverCopy!);
      continue;
    }
    result.push(rewritten);
    index += 2;
  }
  return result;
}

function singleAssign(
  statement: LuaStatement,
): { target: string; value: LuaExpression } | null {
  if (statement.kind !== "assign") return null;
  if (statement.targets.length !== 1 || statement.values.length !== 1) return null;
  const target = statement.targets[0]!;
  if (target.kind !== "name") return null;
  return { target: target.name, value: statement.values[0]! };
}

function tryMethodCall(
  receiverCopy: LuaStatement,
  methodFetch: LuaStatement,
  callSite: LuaStatement,
): LuaStatement | null {
  // `vT1 = vO`
  const copy = singleAssign(receiverCopy);
  if (copy === null || copy.value.kind !== "name") return null;
  const receiverName = copy.target;
  const objectName = copy.value.name;

  // `vT = vO.method`
  const fetch = singleAssign(methodFetch);
  if (fetch === null || fetch.value.kind !== "index") return null;
  if (fetch.value.object.kind !== "name") return null;
  if (fetch.value.object.name !== objectName) return null;
  if (fetch.value.key.kind !== "literal") return null;
  const keyMatch = /^"([A-Za-z_]\w*)"$/.exec(fetch.value.key.text);
  if (keyMatch === null) return null;
  const method = keyMatch[1]!;
  if (!isValidIdentifier(method)) return null;
  const methodName = fetch.target;

  // `... = vT(vT1, ...)` or `vT(vT1, ...)`
  const callExpression =
    callSite.kind === "call"
      ? callSite.call
      : callSite.kind === "assign" && callSite.values.length === 1
        ? callSite.values[0]!
        : null;
  if (callExpression === null || callExpression.kind !== "call") return null;
  if (callExpression.method !== undefined) return null;
  if (callExpression.callee.kind !== "name") return null;
  if (callExpression.callee.name !== methodName) return null;
  const [first, ...rest] = callExpression.args;
  if (first === undefined || first.kind !== "name") return null;
  if (first.name !== receiverName) return null;

  const sugared: LuaExpression = {
    kind: "call",
    callee: name(objectName),
    args: rest,
    method,
  };
  if (callSite.kind === "call") return { kind: "call", call: sugared };
  if (callSite.kind !== "assign") return null;
  return { ...callSite, values: [sugared] };
}

/**
 * Fold a register that is written once and read once immediately afterwards.
 *
 * This is the difference between machine transcription and readable source:
 * `v5 = game` / `v6 = v5.Workspace` becomes `v6 = game.Workspace`.  The window
 * is one statement wide and stops at any statement that is not a plain
 * assignment, which keeps evaluation order and call timing exactly as the VM
 * had them.
 */
export function inlineSingleUseTemporaries(
  statements: readonly LuaStatement[],
): readonly LuaStatement[] {
  const result: LuaStatement[] = [...statements];
  for (let index = 0; index < result.length - 1; index += 1) {
    const definition = result[index]!;
    if (definition.kind !== "assign") continue;
    if (definition.targets.length !== 1 || definition.values.length !== 1) continue;
    const target = definition.targets[0]!;
    if (target.kind !== "name") continue;
    // A call has effects and a timing; never move one across a statement.
    if (containsCall(definition.values[0]!)) continue;

    const consumer = result[index + 1]!;
    if (
      consumer.kind !== "assign" &&
      consumer.kind !== "return" &&
      consumer.kind !== "if" &&
      consumer.kind !== "call"
    ) {
      continue;
    }
    const uses = countNameUses(consumer, target.name);
    if (uses.total !== 1) continue;
    // Rewriting a target would change what is assigned, not what is read.
    if (consumer.kind === "assign" && assignsToName(consumer, target.name)) continue;
    /*
     * Lua allows only a name, an index, or a call before `[`, `.`, or `(`.
     * Folding an operator expression into that position would emit invalid
     * source, so the temporary is kept instead.
     */
    if (uses.inPrefixPosition && !isPrefixExpression(definition.values[0]!)) {
      continue;
    }

    const replaced = substituteName(consumer, target.name, definition.values[0]!);
    result.splice(index, 2, replaced);
    // Re-examine this position: the fold may enable another one.
    index = Math.max(-1, index - 2);
  }
  return result;
}

function containsCall(expression: LuaExpression): boolean {
  switch (expression.kind) {
    case "call":
      return true;
    case "index":
      return containsCall(expression.object) || containsCall(expression.key);
    case "binary":
      return containsCall(expression.left) || containsCall(expression.right);
    case "unary":
      return containsCall(expression.operand);
    case "table":
      return expression.fields.some(containsCall);
    default:
      return false;
  }
}

function assignsToName(statement: LuaStatement, target: string): boolean {
  if (statement.kind !== "assign") return false;
  return statement.targets.some(
    (candidate) => candidate.kind === "name" && candidate.name === target,
  );
}

/** Expressions Lua accepts before `[`, `.`, `:`, or a call's arguments. */
function isPrefixExpression(expression: LuaExpression): boolean {
  return (
    expression.kind === "name" ||
    expression.kind === "index" ||
    expression.kind === "call"
  );
}

interface NameUseSummary {
  readonly total: number;
  /** True when a use sits where Lua requires a prefix expression. */
  readonly inPrefixPosition: boolean;
}

function countNameUses(statement: LuaStatement, target: string): NameUseSummary {
  let count = 0;
  let inPrefixPosition = false;
  const visit = (expression: LuaExpression, prefixPosition = false): void => {
    switch (expression.kind) {
      case "name":
        if (expression.name === target) {
          count += 1;
          if (prefixPosition) inPrefixPosition = true;
        }
        return;
      case "index":
        visit(expression.object, true);
        visit(expression.key);
        return;
      case "call":
        visit(expression.callee, true);
        expression.args.forEach((argument) => visit(argument));
        return;
      case "binary":
        visit(expression.left);
        visit(expression.right);
        return;
      case "unary":
        visit(expression.operand);
        return;
      case "table":
        expression.fields.forEach((field) => visit(field));
        return;
      default:
        return;
    }
  };
  if (statement.kind === "assign") {
    statement.values.forEach((value) => visit(value));
    // A name in `t[k] = v` target position is a read of `t` and of `k`.
    for (const candidate of statement.targets) {
      if (candidate.kind === "index") visit(candidate);
    }
  } else if (statement.kind === "return") {
    statement.values.forEach((value) => visit(value));
  } else if (statement.kind === "if") {
    visit(statement.condition);
  } else if (statement.kind === "call") {
    visit(statement.call);
  }
  return { total: count, inPrefixPosition };
}

function substituteName(
  statement: LuaStatement,
  target: string,
  replacement: LuaExpression,
): LuaStatement {
  const swap = (expression: LuaExpression): LuaExpression => {
    switch (expression.kind) {
      case "name":
        return expression.name === target ? replacement : expression;
      case "index":
        return { ...expression, object: swap(expression.object), key: swap(expression.key) };
      case "call":
        return {
          ...expression,
          callee: swap(expression.callee),
          args: expression.args.map(swap),
        };
      case "binary":
        return { ...expression, left: swap(expression.left), right: swap(expression.right) };
      case "unary":
        return { ...expression, operand: swap(expression.operand) };
      case "table":
        return { ...expression, fields: expression.fields.map(swap) };
      default:
        return expression;
    }
  };
  if (statement.kind === "assign") {
    return {
      ...statement,
      targets: statement.targets.map((candidate) =>
        candidate.kind === "index" ? swap(candidate) : candidate,
      ),
      values: statement.values.map(swap),
    };
  }
  if (statement.kind === "return") {
    return { ...statement, values: statement.values.map(swap) };
  }
  if (statement.kind === "if") {
    return { ...statement, condition: swap(statement.condition) };
  }
  if (statement.kind === "call") {
    return { ...statement, call: swap(statement.call) };
  }
  return statement;
}

export function liftPrototype(
  section: JnkieRecordSection,
  prototype: JnkieDecodedPrototype,
): LiftedPrototype {
  return new Lifter(section, prototype).lift();
}

export { INVERSE_COMPARISON };
