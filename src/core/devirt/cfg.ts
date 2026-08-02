/**
 * Control-flow graph over one prototype's proven opcode effects.
 *
 * Real blocks are laid out in scrambled order and chained by jumps, so a
 * literal transcription is almost entirely `goto`.  Re-ordering blocks so that
 * control usually falls through to the next one removes most of that noise
 * without discarding anything.
 *
 * Reachability is computed but deliberately *not* used to prune.  A static
 * walk from the entry point reaches only about a seventh of this obfuscator's
 * stream, and every recovered API name - `GetService`, `CFrame`, `pcall`,
 * `HttpService` - lands outside it, which shows the dispatcher's control flow
 * is driven by VM state that static analysis cannot follow.  Treating the
 * remainder as dead would hide the actual program, so the figure is reported
 * as information only.
 *
 * An instruction whose opcode was never proven is treated as falling through,
 * which is the conservative assumption.
 */

import type { JnkieOpEffect } from "../recovery/op-effects";

export type BlockTerminator =
  /** Runs off the end of the block into the next instruction. */
  | { readonly kind: "fallthrough"; readonly next: number }
  | { readonly kind: "jump"; readonly target: number }
  | {
      readonly kind: "branch";
      readonly target: number;
      readonly fallthrough: number;
      /** The effect that produced the condition, for rendering. */
      readonly effect: JnkieOpEffect;
    }
  /** Returns or tail-calls; control does not continue in this prototype. */
  | { readonly kind: "exit" };

export interface BasicBlock {
  readonly id: number;
  /** First and last program counter, one-based and inclusive. */
  readonly start: number;
  readonly end: number;
  readonly terminator: BlockTerminator;
  readonly successors: readonly number[];
  /** Block ids that can transfer control here. */
  readonly predecessors: readonly number[];
}

/** Label name for a block, derived from the program counter it starts at. */
export function blockLabel(block: BasicBlock): string {
  return `L${block.start}`;
}

export interface ControlFlowGraph {
  readonly blocks: readonly BasicBlock[];
  /** Block id containing pc 1, or -1 when the prototype is empty. */
  readonly entry: number;
  /** Block ids reachable from the entry. */
  readonly reachable: ReadonlySet<number>;
  /** Map from a program counter to the block that contains it. */
  readonly blockAt: ReadonlyMap<number, number>;
  readonly reachableInstructionCount: number;
  readonly unreachableInstructionCount: number;
}

function successorsOf(
  effect: JnkieOpEffect | null,
  pc: number,
  count: number,
): { targets: number[]; terminates: boolean } {
  if (effect === null) {
    // An unproven opcode is assumed to fall through, never to branch.
    return { targets: [pc + 1], terminates: false };
  }
  switch (effect.kind) {
    case "jump":
      return { targets: [effect.target], terminates: true };
    case "test":
    case "compare-jump":
      return { targets: [pc + 1, effect.target], terminates: true };
    case "for-prep":
      return { targets: [effect.target], terminates: true };
    case "for-loop":
      return { targets: [effect.target, pc + 1], terminates: true };
    case "return":
    case "tailcall":
      return { targets: [], terminates: true };
    default:
      return { targets: [pc + 1], terminates: false };
  }
}

/** True when this effect ends a basic block. */
function isTerminator(effect: JnkieOpEffect | null): boolean {
  if (effect === null) return false;
  return (
    effect.kind === "jump" ||
    effect.kind === "test" ||
    effect.kind === "compare-jump" ||
    effect.kind === "for-prep" ||
    effect.kind === "for-loop" ||
    effect.kind === "return" ||
    effect.kind === "tailcall"
  );
}

export function buildControlFlowGraph(
  effects: readonly (JnkieOpEffect | null)[],
): ControlFlowGraph {
  const count = effects.length;
  if (count === 0) {
    return {
      blocks: [],
      entry: -1,
      reachable: new Set(),
      blockAt: new Map(),
      reachableInstructionCount: 0,
      unreachableInstructionCount: 0,
    };
  }

  // Leaders: the entry, every branch destination, and every pc after a branch.
  const leaders = new Set<number>([1]);
  for (let pc = 1; pc <= count; pc += 1) {
    const effect = effects[pc - 1]!;
    if (!isTerminator(effect)) continue;
    const { targets } = successorsOf(effect, pc, count);
    for (const target of targets) {
      if (target >= 1 && target <= count) leaders.add(target);
    }
    if (pc + 1 <= count) leaders.add(pc + 1);
  }

  const starts = [...leaders].sort((left, right) => left - right);
  const blockAt = new Map<number, number>();
  const blocks: BasicBlock[] = [];

  for (let index = 0; index < starts.length; index += 1) {
    const start = starts[index]!;
    const end = (starts[index + 1] ?? count + 1) - 1;
    for (let pc = start; pc <= end; pc += 1) blockAt.set(pc, index);
    blocks.push({
      id: index,
      start,
      end,
      terminator: { kind: "fallthrough", next: end + 1 },
      successors: [],
      predecessors: [],
    });
  }

  // Second pass: terminators need blockAt to resolve targets to block ids.
  const resolved: BasicBlock[] = blocks.map((block) => {
    const lastEffect = effects[block.end - 1] ?? null;
    const { targets, terminates } = successorsOf(lastEffect, block.end, count);
    const toBlock = (pc: number): number | undefined => blockAt.get(pc);

    let terminator: BlockTerminator;
    if (!terminates || lastEffect === null) {
      terminator = { kind: "fallthrough", next: block.end + 1 };
    } else if (lastEffect.kind === "return" || lastEffect.kind === "tailcall") {
      terminator = { kind: "exit" };
    } else if (lastEffect.kind === "jump" || lastEffect.kind === "for-prep") {
      terminator = { kind: "jump", target: lastEffect.target };
    } else if (
      lastEffect.kind === "test" ||
      lastEffect.kind === "compare-jump" ||
      lastEffect.kind === "for-loop"
    ) {
      terminator = {
        kind: "branch",
        target: lastEffect.target,
        fallthrough: block.end + 1,
        effect: lastEffect,
      };
    } else {
      terminator = { kind: "fallthrough", next: block.end + 1 };
    }

    const successors = targets
      .map(toBlock)
      .filter((id): id is number => id !== undefined);

    return { ...block, terminator, successors: [...new Set(successors)] };
  });

  // Predecessors, needed by the structuring pass to prove a region has a
  // single entry before wrapping it in an .
  const predecessors = resolved.map((): number[] => []);
  for (const block of resolved) {
    for (const successor of block.successors) {
      predecessors[successor]?.push(block.id);
    }
  }
  const withPredecessors = resolved.map((block) => ({
    ...block,
    predecessors: predecessors[block.id] ?? [],
  }));

  // Reachability from the entry block.
  const entry = blockAt.get(1) ?? -1;
  const reachable = new Set<number>();
  if (entry >= 0) {
    const queue = [entry];
    reachable.add(entry);
    while (queue.length > 0) {
      const id = queue.pop()!;
      for (const next of withPredecessors[id]?.successors ?? []) {
        if (!reachable.has(next)) {
          reachable.add(next);
          queue.push(next);
        }
      }
    }
  }

  let reachableInstructionCount = 0;
  for (const id of reachable) {
    const block = withPredecessors[id]!;
    reachableInstructionCount += block.end - block.start + 1;
  }

  return {
    blocks: withPredecessors,
    entry,
    reachable,
    blockAt,
    reachableInstructionCount,
    unreachableInstructionCount: count - reachableInstructionCount,
  };
}

/**
 * Choose an emission order that maximizes fall-through.
 *
 * Following each block's preferred successor before its alternative turns most
 * jumps into adjacency, which is what removes the `goto` chains: a jump to the
 * block emitted next needs no jump at all.
 *
 * Every block is placed, reachable or not - see the note at the top of this
 * file on why static reachability is not trustworthy here.
 */
export function orderBlocks(cfg: ControlFlowGraph): readonly number[] {
  const order: number[] = [];
  const placed = new Set<number>();
  if (cfg.blocks.length === 0) return order;

  const preferred = (block: BasicBlock): number | null => {
    switch (block.terminator.kind) {
      case "fallthrough":
        return cfg.blockAt.get(block.terminator.next) ?? null;
      case "jump":
        return cfg.blockAt.get(block.terminator.target) ?? null;
      case "branch":
        // Prefer the fall-through so a conditional reads as `if ... then`.
        return cfg.blockAt.get(block.terminator.fallthrough) ?? null;
      default:
        return null;
    }
  };

  // Seed with the entry, then any remaining block in address order.
  const pending: number[] = cfg.entry >= 0 ? [cfg.entry] : [];
  const byAddress = cfg.blocks.map((block) => block.id);

  for (;;) {
    let seed: number | undefined = pending.shift();
    while (seed !== undefined && placed.has(seed)) seed = pending.shift();
    if (seed === undefined) {
      seed = byAddress.find((id) => !placed.has(id));
      if (seed === undefined) break;
    }

    let current: number | null = seed;
    while (current !== null && !placed.has(current)) {
      placed.add(current);
      order.push(current);
      const block = cfg.blocks[current]!;
      // Queue the alternative branch so it is emitted soon after.
      for (const successor of block.successors) pending.push(successor);
      const next: number | null = preferred(block);
      current = next !== null && !placed.has(next) ? next : null;
    }
  }
  return order;
}
