# Recovery limits

What the devirtualizer currently reaches on VM-protected input, what blocks the
rest, and which approaches were tried and ruled out. Recorded so the negative
results are not re-derived.

## Where it gets to

Measured on an authorized Luraph-family sample, target-script section:

| | |
|---|---|
| Functions emitted | 371 |
| Instruction records | 34,696 |
| Reachable | 29,825 (86%) |
| Lifted to source | 23,579 (79.1% of reachable) |
| Explained incl. decoder protocol | **93.3%** |
| Genuinely unresolved | 1,999 |
| Output | ~20,400 lines, re-parses |
| `goto` / labels | 925 / 633 |
| Natural loops recovered | 74 |
| Globals resolved by name | 40 |
| Functions referencing a nameable global or string | 44 of 371 |

Recovered names include `game`, `Instance`, `Enum`, `CFrame`, `Vector3`,
`UDim2`, `GetService`, `HttpService`, `Connect`, `Destroy`, `loadstring`,
`pcall`, `setmetatable`, `identifyexecutor`.

## What blocks full recovery

**String constants are encrypted.** 4,445 of them in the VM section, and the
strings that say what the script *does* are among them. They are assembled at
runtime through helper calls, so the output shows structure without meaning:

```lua
v14 = VM_RUNTIME[7]
v15 = "\134"
v15 = v15(v16)
v14 = v14 + v15
```

**The VM's helper table is opaque.** `VM_RUNTIME[n]` indexes a table of 122
functions whose keys are mangled to one and two character names (`xm`, `KA`,
`YA`). Knowing what a slot does means reading its body.

**Every route to those bodies runs through flattened control flow.** The
recovered loader is itself dispatcher-flattened: 150 functions, 33 dispatchers,
65 `while true` loops, 336 bitwise operations.

## Approaches tried and ruled out

**Static reachability pruning, before branch modes were fixed.** Reached 15% of
the stream and excluded every recovered API name. That looked like proof the
control flow was un-analysable; it was actually a bug - branch operands carry
an addressing mode that was being ignored. After fixing it reachability is 86%
and pruning is sound. *Recorded because the wrong conclusion was drawn once.*

**Back-edge loop wrapping without dominance.** Produced `while true do goto L5`
- loops whose first statement jumped out of them. Correct but less readable
than the goto it replaced. Dominance analysis was the missing piece.

**Dispatcher walking with a persistent store.** Threads one value store across
state blocks, which is what the memoized next-state pattern needs. Reaches one
or two states then stops: state bodies contain nested dispatchers that exhaust
the step budget, and calls invalidate the store. Edge recovery 0-2 of ~100
states.

**Cryptanalysis of the encrypted constants.** Tested identity, XOR by a
constant, by position, by length, by constant index, by index plus position,
addition and subtraction of position and index, byte reversal, and all 256
single-byte XOR keys, scoring by printable share against a crib from a related
sample's plaintext VM vocabulary.

| Family | All-printable share |
|---|---|
| every positional and index-keyed transform | ~0.7% |
| best of 256 single-byte XOR keys | 0.9% |

Raw constants are high entropy (`0b2f06a9bed2`, `b4a3f7142c457f`). The scheme
is per-constant keyed or a stream cipher; it cannot be recovered by inspection.

**Extracting the opcode table from the loader's dispatch structure.** The
loader holds one 159-field table with 122 function values and eight
`T[<number>] = function` assignments. The table's keys are mangled identifiers,
so it carries no semantics without reading the function bodies - which returns
to the flattened-control-flow wall.

## What would actually close it

Symbolic execution that models nested dispatch and call effects across the
loader's 150 functions, yielding a machine-checked opcode specification, the
helper table's meaning, and the decryption routine. That is a research-scale
build, not an incremental pass, and it is the single prerequisite for all three
remaining unknowns.

## The permanent ceiling

Even with all of the above, the result is semantically equivalent readable Lua,
not the original file. Local names, comments, and source layout are destroyed
by compilation and are synthesized here (`v12`, `fn37`), which the emitted
header states. Any claim to have recovered the original is fabrication.
