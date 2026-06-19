# CodeScrambler, explained from the ground up

This document explains **every** idea in CodeScrambler starting from zero. It
uses plain-language pictures, then immediately pins each picture to the exact
technical thing it stands for — so a curious beginner and a reverse-engineering
expert can both read it and end up at the same precise mental model. Nothing is
dumbed *down*; it is built *up*.

If you want the dense engineering reference, read
[ARCHITECTURE.md](ARCHITECTURE.md). This file is the on-ramp to it.

---

## 1. What is the thing we are editing?

**Picture.** A program on Windows (a `.exe` or `.dll`) is like a *pre-packed
moving truck*. There are labeled boxes (code, text, pictures, settings), a
packing list that says which box is where, and a sticky note on the door saying
"open this box first."

**Precisely.** That file is a **PE file** (Portable Executable). It has:
- a **header** (the packing list): where each part lives, how big it is, where
  Windows should start running ("open first" = the **entry point**);
- **sections** (the boxes): `.text` holds machine code (CPU instructions),
  `.data`/`.rdata` hold variables and constants, `.rsrc` holds resources, and
  there can be *any* number of custom sections with *any* names;
- **directories** (special index cards) pointing at things the OS must fix up
  while loading: imports (functions borrowed from other DLLs), exports (functions
  we lend out), relocations (addresses to patch if we load somewhere else), TLS
  callbacks (code that runs per-thread), and exception tables.

**Our promise.** When CodeScrambler rewrites the truck, *every box still works*,
the packing list still matches, and the "open first" note still points somewhere
valid — even for weird, non-standard boxes. That is what "PE fidelity" means.

---

## 2. What does "scramble" / "obfuscate" actually mean?

**Picture.** Take a clear set of LEGO instructions and rebuild them so the model
is **identical when finished**, but the instruction booklet is now 300 confusing
pages full of detours, decoys, and a few steps written in a secret code only a
tiny built-in decoder understands.

**Precisely.** We apply **semantics-preserving transformations**: the program's
observable behavior is unchanged, but its *form* is much harder to read,
disassemble, or modify. We do this at the level of CPU instructions and PE
structure.

**Two flavors of "different every time" (read this — people mix them up):**
- **Polymorphic** = you keep the *same booklet* but lock it in a different box
  with a different key each time. Open the box and the booklet inside is the
  same. *(Here: encryption + the VM's secret language — the wrapper changes.)*
- **Metamorphic** = you literally *rewrite the booklet* — different words, same
  finished model — so there is **no** identical booklet hiding inside any box.
  *(Here: the mutation engine rewrites the real instructions.)*

CodeScrambler is **both**: a metamorphic core (rewritten instructions) wrapped in
polymorphic layers (encryption + VM). Run it again with a new dice number and you
get a genuinely different program body, not just a different lock. See §13 for the
scorecard, and the README for the side-by-side table.

---

## 3. The assembly line (the whole pipeline in one breath)

**Picture.** A factory line: unpack the truck → turn every instruction into a
labeled LEGO brick → let several robots rearrange/disguise the bricks → snap the
bricks back into machine code → repack the truck and fix the packing list.

**Precisely:**

```
PE file ──▶ loader ──▶ IR (bricks) ──▶ passes (robots) ──▶ assembler ──▶ writer ──▶ new PE file
            (read)     symbolic code    transformations    bytes+map     rebuild
```

- **loader** reads the PE and **disassembles** code into our IR.
- **IR** = Intermediate Representation = the bricks (see §5).
- **passes** = the transformations (mutation, virtualization, hardening).
- **assembler** turns bricks back into bytes and tells us where everything moved.
- **writer** rebuilds the PE and repairs all the index cards.

Each stage is a separate, importable Python module. You can grab just the robots,
or just the brick model, and use them in your own project.

---

## 4. Randomness with a memory (the RNG)

**Picture.** A magic dice cup. If you whisper a number ("seed") to it first, it
rolls the *exact same sequence* forever — great for reproducing a build. If you
don't, it rolls fresh every time — great for making each build unique.

**Precisely.** One **seeded pseudo-random number generator** (`core/rng.py`,
`Rng`) is the *single* source of every choice: which junk to insert, which VM
opcode means "add" today, which cipher key, which section name. Same seed →
byte-for-byte identical output. No seed → true polymorphism. Rule: transform code
**never** calls bare `random`; it always asks the `Rng`. That is what makes
"different every time" and "perfectly reproducible" both true.

---

## 5. The bricks (the IR) and the sticky notes (labels)

**Picture.** Every instruction becomes a LEGO brick with a card on it: what it
does, what it touches, and — importantly — *which other brick it points to* is
written as a **named sticky note**, not a street address.

**Precisely.** `core/ir.py` defines `Program → Section → Instruction`. An
`Instruction` records its mnemonic/operands, original bytes, which registers and
**CPU flags** it reads/writes, and branch metadata. The key trick: a jump's
target is stored as a **symbolic label** (a name) instead of a fixed address.

**Why this matters (the central problem of binary rewriting).** If jumps used
raw addresses and you insert one byte, *every* later address shifts, so every
jump becomes wrong. By naming targets ("go to brick `L7`") instead of numbering
them ("go to byte 0x1A3F"), you can insert, delete, and reorder bricks freely;
the real addresses are computed *once at the very end*.

---

## 6. Reading and writing machine code (disasm ↔ asm)

**Picture.** Two translators: one reads raw bytes aloud as instructions
(disassembler), one writes instructions back down as bytes (assembler).

**Precisely.**
- **Disassembler** (`core/disasm`, **capstone** backend): bytes → IR, filling in
  registers/flags/branches. `DisassemblerBackend` is an extension point if you
  ever want another decoder.
- **Assembler** (`core/asm`, **keystone**): IR → bytes. It runs a **two-pass
  fixpoint**: guess sizes → lay out addresses (recording where each label lands)
  → re-encode the size-sensitive bricks (branches, RIP-relative, synthetic)
  against those addresses → repeat until nothing changes. Bricks that didn't
  change keep their **original bytes verbatim**, so most of the program is
  byte-perfect and only the few edited bricks are re-encoded.

Output includes the crucial **`old address → new address` map** used to repair
the PE.

---

## 7. The robots, part 1 — the Mutation engine

These are the "confusing booklet" tricks (`codescrambler/mutation`). Each is a
`Pass`. The golden safety rule for all of them: **only clobber a register or a
CPU flag if we can prove it's already dead; otherwise skip.** Better a no-op than
a wrong program.

| Robot (pass) | Picture | Precisely |
|---|---|---|
| **junk** | sprinkle harmless filler steps | insert register/flag-preserving no-effect instructions |
| **opaque** | a fork in the road that *always* goes left, with a fake right path | an always-true predicate guarding dead code, wrapped in `pushf/popf` so flags survive |
| **substitute** | say the same thing a different way | `mov a,b` → `lea a,[b]` or `push b; pop a` |
| **jumps** | take a pointless detour that returns | insert `jmp` to the very next brick |
| **callswitch** | replace "call" with "leave a note then jump" | `call t` → `push return; jmp t` (x86) |
| **mba** | rewrite `2+3` as `((2^3)+2*(2&3))…` | Mixed Boolean-Arithmetic identities, **checked by actual arithmetic** before use |
| **constants** | hide a number behind a scratch-off | `mov r,N` → `mov r,N^k; xor r,k` |
| **reorder** | shuffle two steps that don't depend on each other | swap adjacent independent instructions |
| **antidisasm** | glue a fake clue right after a guaranteed turn | `jmp over; .byte <decoy>; over:` — the decoy is **unreachable**, so a linear-sweep disassembler mis-reads it but the CPU never runs it |
| **scatter** | cut the story into scenes and shuffle them | split into basic blocks, shuffle their order, relink fall-throughs with explicit `jmp`s (built on `core/cfg.py`) |
| **branchfunc** | take a side door instead of the marked exit | replace `jmp t` with a stack trick (`push {t}; ret`, or x64 `push rax; mov rax,{t}; xchg rax,[rsp]; ret`) so the direct edge vanishes |
| **stacknoise** | step left then right — net zero | balanced `lea rsp,[rsp±N]` |

**Why several of these are provably safe.** `mba`, `constants`, the lifter and
the ciphers all **self-check**: they compute the original and the rewritten
result numerically and refuse to emit anything that doesn't match. `antidisasm`
is safe by *construction*: the decoy bytes sit strictly between a jump and its
target, so they can never execute.

---

## 8. The robots, part 2 — the Virtualization engine (the secret language)

**Picture.** Pick a handful of real instructions and *retranslate* them into a
made-up private language. Ship a tiny **interpreter** that's the only thing in
the world able to read that language, and write the translated program in
**encrypted** ink. To understand the code, an attacker must first reverse the
interpreter, then the language, then the encryption — and **all three change
every build**.

**Precisely** (`codescrambler/vm`):
- **ISA** (`isa.py`): a small register-based virtual CPU (LDI, MOV, ADD, SUB,
  XOR, AND, OR, ADDI, EXIT) with a reference `simulate()` for checking.
- **Randomizer** (`randomizer.py`): per build, shuffles which **opcode number**
  means which operation, picks fresh encryption keys, reorders handlers, and
  remaps real registers to VM slots. This is the polymorphism.
- **Bytecode** (`bytecode.py`): encode the VM program, **encrypt** it (rolling
  XOR), with a verified decrypt/decode round-trip.
- **Lifter** (`lifter.py`): turns a run of real instructions into VM bytecode,
  and **numerically self-checks** the run is equivalent. It refuses anything
  touching the stack pointer (`rsp`/`esp`).
- **Interpreter generator** (`interpreter.py`): emits fresh x64 assembly for the
  dispatcher + handlers that execute the bytecode.

Status note: the building blocks are verified off-target; *replacing the native
code with a call into the interpreter inside the rebuilt PE* ("commit") is
specified but **gated** until validated on a real machine — because we will not
ship a runtime rewrite we couldn't prove safe here.

---

## 9. The robots, part 3 — the Protection engine (the locked boxes)

**Picture.** Lock the non-code boxes (data, resources) with a combination lock.
Slip a tiny **doorman** in front of the "open first" note: when the program
starts, the doorman dials the combinations, unlocks the boxes, then sends control
to where it was originally meant to go. On disk the boxes look like noise.

**Precisely** (`codescrambler/protect`):
- **Ciphers** (`ciphers.py`): randomized `XorRolling`/`AddRolling`, each with a
  Python `encrypt` and a **matching hand-written x64 `decrypt` in assembly**, and
  a self-test proving they're inverses.
- **Stub** (`stub.py`): a **position-independent** decryptor (it finds its own
  address with a `call/pop` trick, so it works regardless of where Windows loads
  it). It saves registers, decrypts each protected section in place, then jumps
  to the **original entry point**.
- **Selection** (`sections.py`): chooses only **safe** non-executable sections to
  encrypt (never the ones the loader reads before our doorman runs), marks them
  writable, installs the stub, and repoints the entry — all via a writer hook.

---

## 10. The robots, part 4 — the Hardening engine (alarms, signatures, seals)

This is the newest engine (`codescrambler/harden`). It covers the *preventive*
and *tamperproofing* ideas from the protection literature.

- **Anti-debugging — "is someone watching?"**
  *Picture:* a guard that quietly checks if an inspector is in the room and, if
  so, slams the door.
  *Precisely:* `AntiDebugPass` reads the OS's `BeingDebugged` flag straight from
  the **PEB** (x64 `gs:[0x60]`, x86 `fs:[0x30]`, byte `+2`) with **no imports**.
  If a debugger is attached, it runs a response (default `ud2`, a deliberate
  crash). It saves/restores the one register and the flags it uses, so the
  surrounding program is unaffected when no debugger is present.

- **Anti-VM — "am I in a lab, not the real world?"**
  *Picture:* a guard that checks whether the room is a film set instead of a real
  building, and bails if so.
  *Precisely:* `AntiVMPass` runs `CPUID` and checks the "hypervisor present" bit
  (leaf 1, ECX bit 31). Many automated sandboxes run inside VMs where that bit is
  set. Register/flag-neutral, configurable response, opt-in (real users use VMs
  too).

- **Watermarking — "whose copy is this?"**
  *Picture:* an invisible signature pressed into the paper. You can't see it, but
  with the right light you can read exactly who this copy belongs to.
  *Precisely:* `Watermark` embeds a hidden identifier as a small data section
  (`.csmark`, lightly XOR-scrambled with the key carried alongside it).
  `extract_watermark(path)` reads it back from the file later. Adding a benign
  data box can't change behavior, so this is fully committed.

- **Tamperproofing — "has anyone edited me?"**
  *Picture:* a wax seal over a page. The program re-checks the seal while running;
  if a cracker scratched out a check (a "NOP"), the seal no longer matches and the
  program reacts.
  *Precisely:* `checksum()` (32-bit FNV-1a, self-tested) plus a `GuardGenerator`
  that emits a position-independent runtime hash-and-compare guard. The
  *building blocks* are verified; **inserting** guards and **patching** their
  expected value at build time is **gated** (you must pick a code range that
  excludes the guard's own patched number, or the seal would invalidate itself).

- **Anti-(AI/LLM)-analysis deterrent — "no trespassing, robots included"**
  *Picture:* a clearly worded sign on the door. It can't physically stop anyone,
  but it states the rules and tells automated visitors to turn around.
  *Precisely:* `LlmDeterrent` embeds a readable notice (its own section) telling
  automated/AI/LLM tools to refuse disassembly, decompilation, and decryption —
  so when someone pastes the file (or its `strings`) into a model, the model
  reads an explicit instruction to decline. `extract_notice(path)` reads it back.
  This is a **deterrent layered on top of** the real obfuscation, never a
  replacement for it — a compliant tool may heed it; a determined one won't.

---

## 11. Repacking the truck (the PE writer) and fixing every index card

**Picture.** After the robots finish, we don't squeeze the new bricks back into
the old box (they may not fit). We add a **brand-new box** for the rewritten
code, change the "open first" note to point at it, and then walk through every
index card to update any address that moved.

**Precisely** (`codescrambler/pe`):
- **writer.py**: appends a new executable section with the reassembled code,
  redirects the entry point, and runs post-build hooks (protection, watermark).
- **reloc.py**: reads existing base relocations and **builds new ones** for the
  moved code, so Windows' address-randomization (ASLR) still works.
- **fidelity.py**: uses the `old→new` map to retarget **TLS callbacks, exports,
  exception tables (`.pdata`/`.xdata`), and SAFESEH** so structured exception
  handling, multithreading, and exported APIs keep working.

This is the part that makes "the binary still runs" true rather than hopeful.

---

## 12. Why it (almost) can't quietly break your program — the invariants

Every robot obeys the same small set of rules. In kid terms, then exactly:

1. *Don't number the bricks, name them.* → symbolic labels; addresses resolved
   last by the two-pass assembler.
2. *If you'll mess up a flag, save it first.* → only touch flags proven dead, or
   wrap in `pushf/popf`.
3. *If you'll borrow a register, give it back.* → balanced `push/pop`,
   pointer-width only.
4. *Never touch the stack pointer's value.* → `rsp`/`esp` is never virtualized or
   net-changed.
5. *Check your own math before trusting it.* → MBA, constants, lifter, ciphers
   self-verify numerically.
6. *When in doubt, do nothing.* → if safety can't be proven, the pass **skips and
   counts** the opportunity rather than risk a wrong program.

These are why we can ship transforms confidently even though final *runtime*
validation on real binaries is left to you (on an isolated VM).

---

## 13. How this maps to the textbook (Surreptitious Software)

The standard reference (Collberg & Nagra) splits software protection into
**obfuscation, tamperproofing, watermarking, birthmarking,** and **hardware
anti-piracy**. Here's the honest scorecard in one glance:

- **We do:** opaque predicates, dead/junk code, reordering, **block scattering**,
  **branch functions**, **virtualization** (table interpretation), control
  indirection, **MBA** + constant encoding, data/section **encryption**,
  instruction substitution, **anti-disassembly**, **anti-debugging** (PEB +
  NtGlobalFlag), **anti-VM** (CPUID), **static watermarking**, **checksum-guard
  tamperproofing** (building blocks), an **anti-(AI/LLM)-analysis deterrent**, and
  strong diversity (**metamorphic** body + **polymorphic** wrapping).
- **We partly do (designed, gated):** tamper-guard insertion, VM native-code
  commit, encrypting *executable* sections.
- **We deliberately left for later:** *full* control-flow flattening (we ship the
  CFG model + block scattering; full flattening needs a persistent state slot),
  register renaming, function inline/outline/clone, per-string inline encryption,
  oblivious hashing, dynamic (CT) watermarking, **runtime metamorphism** (a
  self-rewriting stub — we're metamorphic at *build* time), and white-box crypto.
  Birthmarking and hardware dongles are *out of scope* (the first is an
  identification technique, not a protection; the second needs external hardware).

The full table — including exactly *how* to add each missing one — is
[ARCHITECTURE.md §13](ARCHITECTURE.md); the complete implemented + roadmap
inventory is [FEATURES.md](FEATURES.md).

---

## 14. Where to look in the code (a tiny treasure map)

| You want to understand… | Open this |
|---|---|
| the bricks | `codescrambler/core/ir.py` |
| grouping bricks into scenes (basic blocks) | `codescrambler/core/cfg.py` |
| read/write machine code | `codescrambler/core/disasm/`, `codescrambler/core/asm/` |
| the dice cup | `codescrambler/core/rng.py` |
| the confusing-booklet robots | `codescrambler/mutation/*.py` |
| the secret language | `codescrambler/vm/*.py` |
| the locked boxes | `codescrambler/protect/*.py` |
| alarms / signatures / seals | `codescrambler/harden/*.py` |
| repacking + fixing index cards | `codescrambler/pe/*.py` |
| the whole line wired together | `codescrambler/engine.py`, `cli.py`, `config.py` |

Start at the brick (`ir.py`), then follow one robot end to end, then read the
writer. After that, the dense [ARCHITECTURE.md](ARCHITECTURE.md) will feel like a
map of a city you've already walked.
