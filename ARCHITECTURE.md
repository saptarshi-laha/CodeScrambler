# CodeScrambler — Architecture (top to bottom)

This document is the handover reference. It explains the whole system from the
bottom layer up, states the **correctness invariants** every transform relies
on, records the **maturity** of each piece (what is verified off-target vs. what
needs validation on a Windows host), and lists the **exact continuation steps**
for anything left open. If you are an assistant picking this up: read this file
first, then the module docstrings — every module has a thorough header.

---

## 1. What it is

CodeScrambler is a **metamorphic + polymorphic** PE obfuscation toolkit with four
independent, individually-importable engines wired together by a small
orchestrator. *Metamorphic* = the mutation engine rewrites the real instruction
stream (no constant body); *polymorphic* = the VM and protection engines wrap
code in a fresh encryptor/opcode-map every build. (See §1.1.)

- **Mutation engine** (`codescrambler.mutation`) — junk, opaque predicates,
  instruction substitution, jump obfuscation, call switching, MBA expansion,
  constant unfolding, reordering, stack noise, anti-disassembly, block
  scattering, branch functions.
- **Virtualization engine** (`codescrambler.vm`) — lifts native instruction
  runs into per-build randomized, encrypted bytecode for a generated VM
  interpreter.
- **Protection engine** (`codescrambler.protect`) — encrypts non-executable
  sections at rest and installs a position-independent runtime decryptor stub.
- **Hardening engine** (`codescrambler.harden`) — preventive + tamperproofing
  transforms: anti-debugging, static watermarking, self-checksum guards, and an
  anti-(automated/AI/LLM)-analysis deterrent.

Everything is driven by a single seeded RNG (`codescrambler.core.rng.Rng`), so:
- **with a seed** → fully reproducible builds;
- **without a seed** → a different output every run — metamorphic body (rewritten
  instructions) + polymorphic wrapping (opcode maps, cipher keys, junk,
  predicates, section names all change).

### 1.1 Metamorphic vs polymorphic (terminology)
- **Polymorphic**: the *wrapper* varies per build (encryptor/decryptor, VM opcode
  map, keys) while the decrypted body is effectively constant. Here: `protect`
  (per-build cipher/key/stub) and `vm` (per-build opcode map/handler order/keys).
- **Metamorphic**: the *body itself* is rewritten — different instructions,
  same semantics, no constant payload to signature, and divergence even across
  generations. Here: `mutation` (substitution, MBA, reorder, junk, opaque,
  antidisasm, constants, callswitch, stacknoise), enabled by disassembling input
  to a symbolic IR and re-emitting it. Feeding an output back through the tool
  yields a further-diverged variant.
- This is a **static** metamorphic rewriter (variants generated at build time).
  *Runtime* metamorphism (a self-rewriting stub that mutates on each execution)
  is on the roadmap — see FEATURES.md.

Design priorities, in order: **(1) never emit a broken binary for the parts that
are committed, (2) keep every component independently usable, (3) make the code
human-reviewable.** Where runtime correctness cannot be proven off-target, the
feature is gated behind an explicit opt-in and documented here.

---

## 2. Layered overview

```
            CLI  (codescrambler/cli.py)            python -m codescrambler.mutation / .vm
              │                                         │
              ▼                                         ▼
        Engine (engine.py)  ───────────────►  Mutator / Virtualizer (standalone)
              │  composes pipeline from Config
              ▼
   ┌──────────────────────────── passes ────────────────────────────┐
   │  mutation.*   vm.VirtualizePass   harden.*   (your custom Pass)  │
   └─────────────────────────────────────────────────────────────────┘
              │ operate on the IR (Program/Section/Instruction)
              ▼
        core/  (the shared substrate)
        ├── rng.py         seeded, splittable RNG
        ├── ir.py          Program / Section / Instruction (+ flag/branch helpers)
        ├── disasm/        capstone backend (+ DisassemblerBackend ABC)  → IR
        ├── asm/           two-pass keystone assembler            IR → bytes + VA map
        ├── pass_base.py   Pass contract + registry
        ├── synth.py       pass-authoring helpers (LabelMaker, synth_branch, …)
        ├── analysis.py    conservative flag/register liveness helpers
        └── cfg.py         basic-block model (foundation for CFG transforms)
              ▲
              │ load / rebuild
        pe/   (PE fidelity)
        ├── loader.py      pefile → IR (all executable sections, any name)
        ├── writer.py      IR → rebuilt PE (new section + OEP redirect + hooks)
        ├── reloc.py       read / remap / rebuild base relocations
        └── fidelity.py    retarget TLS / exports / exceptions / SAFESEH
```

Dependency rule: **engines depend on `core` (and `pe`), never on each other.**
This is enforced by keeping every cross-cutting helper in `core`: the pass
contract (`core/pass_base.py`), synthetic-instruction helpers (`core/synth.py`)
and liveness helpers (`core/analysis.py`) all live there, so `mutation`, `vm`,
`protect` and `harden` can each be imported in a fresh process **without pulling
in the others** (regression-tested in `tests/test_core.py`). `mutation.base` /
`mutation.analysis` remain as thin re-exports for backward compatibility.
`Engine` imports an engine lazily and only when its knob is non-zero.

---

## 3. The core substrate (`codescrambler/core`)

### 3.1 `rng.py` — polymorphism source
A thin wrapper over `random.Random` with a recorded resolved `seed`, plus
helpers (`randint`, `choice`, `sample`, `shuffle`, `shuffled`, `chance`,
`bits`, `spawn`). **Rule: every transform draws all randomness from the passed
`Rng`.** That is what makes builds both reproducible (seeded) and polymorphic
(unseeded). `spawn()` derives child RNGs for independent sub-streams.

### 3.2 `ir.py` — the intermediate representation
- `Arch` — `X86`/`X64` with `pointer_size`.
- `Instruction` — the unit every pass manipulates. Key fields/derived props:
  - `mnemonic`, `op_str`, `address` (None for synthetic), `raw` (original bytes).
  - control-flow: `is_branch`, `is_cond_branch`, `is_call`, `is_ret`,
    `branch_label` (symbolic target), `is_terminator`.
  - RIP-relative info; `regs_read` / `regs_written` (capstone-populated).
  - **flag liveness inputs:** `reads_flags` / `writes_flags` (derived from the
    capstone flags register appearing in the reg sets).
  - synthesis: `synthetic`, `text` (verbatim asm), `label` (defines a label at
    this instruction), `label_refs` (names referenced inside `text` as
    `{name}` — resolved to absolute addresses by the assembler).
  - constructors: `Instruction.synth("mov rax, rbx")`,
    `Instruction.synth_ref("push {ret}", ("ret",))`.
- `Section` — name, rva, raw bytes, characteristics, `is_executable`,
  `instructions`.
- `Program` — `arch`, `image_base`, `entry_rva`, `sections`, `metadata` dict
  (used to pass engine artifacts to the writer). Helpers: `executable_sections()`,
  `all_instructions()`, `entry_va`.

**Why symbolic branches matter:** passes insert/remove/reorder instructions
freely; concrete displacements are only computed at assembly time from labels,
so movement never corrupts control flow.

### 3.3 `disasm/` — bytes → IR
- `capstone_backend.py`: detail mode, `skipdata` on. Data bytes (`insn.id == 0`)
  become `.byte` instructions without touching group/reg APIs. Populates the
  rich metadata (reg read/write sets, flag access) liveness analysis needs.
- `base.DisassemblerBackend`: the ABC to implement for a custom decoder;
  `get_backend()` returns the default capstone backend, and `PELoader` accepts
  any backend instance.
- `base.label_branches()`: after decoding, assigns labels to branch targets that
  land on a decoded instruction (cross-section aware).

### 3.4 `asm/assembler.py` — IR → bytes (two-pass)
Iterative layout: estimate sizes, place instructions, then re-encode only the
size-sensitive ones (branches, RIP-relative, synthetic) while preserving
original bytes for untouched instructions. Resolves:
- `branch_label` → absolute target (keystone computes the displacement),
- `label_refs` `{name}` placeholders in synthetic `text` → absolute addresses.

Output: `AssembledCode(data, address_map)` where `address_map` maps every
original instruction VA → new VA. **This map is the backbone of PE fidelity.**

### 3.5 `pass_base.py` — the plugin contract
`Pass.apply(program, rng) -> PassReport`. `@register` records a pass by `name`;
`registered_passes()` / `get_pass()` expose the registry. Third-party passes
implement the same contract without importing any engine.

### 3.6 `synth.py` — pass-authoring helpers
`LabelMaker.fresh(prefix)` (process-unique labels), `synth_branch(mnemonic,
label)` (label-targeted synthetic branch), `synth_labeled(text, label)`,
`rebuild_section`, `iter_executable`. Living in `core` lets `mutation`, `harden`
and third-party passes synthesize control flow without depending on each other.

### 3.7 `analysis.py` — conservative liveness
`flags_dead_after`, `register_dead_after`, `gp_registers` — pessimistic helpers
(a label/branch/call/ret or the window end counts as "live") so a pass can only
ever *skip* an opportunity, never miscompile. Shared by `mutation` and `vm`.

### 3.8 `cfg.py` — basic-block model
`build_blocks(instructions)` partitions the flat list into `BasicBlock`s (leaders
= first instruction, post-branch/return instructions, and every labelled
instruction — a safe over-approximation), and `flatten_blocks(blocks)`
concatenates them back. Each block exposes `label`, `terminator` and
`falls_through`. This is the foundation for control-flow transforms (block
scattering today; flattening/loops later). Property: `flatten_blocks(build_blocks(x)) == x`.

---

## 4. PE fidelity (`codescrambler/pe`)

### 4.1 Strategy (packer-style, robust)
1. Assemble **all** executable sections as one listing at a fresh base VA — this
   lets branches cross section boundaries and yields a complete VA map.
2. Append the blob as a **new executable section**; repoint the entry to the
   moved entry instruction. Original sections stay (now dead) so any
   absolute reference we did not catch still finds plausible bytes.
3. Rebuild base relocations for moved code; retarget code-referencing
   directories.

### 4.2 `loader.py`
`pefile` → `Program`. Iterates sections by characteristics (handles **arbitrary
/ non-standard section names**), disassembles executable ones, runs
`label_branches`. Detects arch from optional-header magic.

### 4.3 `writer.py`
- `add_section(name, raw, characteristics) -> rva` (appends at write time).
- `add_post_hook(hook)` — **the extension seam** the VM-commit and protection
  engines use; hooks run after relocations + fidelity, before serialization, and
  can add sections and override `new_entry_rva`.
- `write()`: assemble code → add code section → set entry → rebuild relocs →
  `Fidelity.retarget_all()` → run hooks → serialize by byte-patching a copy of
  the original file (header section count, AddressOfEntryPoint, SizeOfImage,
  section table, reloc directory).

### 4.4 `reloc.py` / `fidelity.py`
- `reloc`: read existing entries, emit new entries for moved targets (keeping
  originals for the dead copy), serialize per-page `.reloc` blocks.
- `fidelity`: retarget TLS callbacks, export address table, x64 exception table
  (`.pdata` BeginAddress via direct dword patching), x86 SAFESEH handlers — all
  through the VA map.

**Maturity:** the full load → (zero transforms) → rebuild round-trip was
exercised in memory in earlier phases (new section added, entry redirected,
SizeOfImage updated). End-to-end *execution* on a real binary is left to you
(no PE files are produced in this environment by request).

---

## 5. Mutation engine (`codescrambler/mutation`) — IMPLEMENTED & VERIFIED

All passes were verified in memory: decode a code blob → apply pass →
re-assemble with keystone → valid bytes. MBA/constants additionally self-check
their math numerically. **None of these create PE files.**

### 5.1 Safety model (read this before adding passes)
Every pass keeps the program correct by one of two means:
- **Construction:** emit only register- and flag-preserving code (junk, opaque,
  stack-noise, the `lea`/`push;pop` substitutions). Safe to splice anywhere.
- **Proof:** only clobber flags/regs where analysis proves them dead. Flag
  liveness is `mutation/analysis.flags_dead_after` — *conservative*: a label,
  branch, call, ret or the end of the window all count as "live". A pass that
  can't prove safety **skips** the opportunity (never miscompiles).

Shared helpers: `analysis.py` (liveness, scratch regs), `catalog.py`
(generative junk + opaque predicate factories, `pushf/popf`, stack-pointer
names), `base.py` (`Pass`/`register` re-export, `LabelMaker`, `synth_branch`,
`synth_labeled`).

### 5.2 The passes
| name | what | correctness basis |
|------|------|-------------------|
| `junk` | splice register/flag-preserving junk | preserving by construction |
| `opaque` | always-true predicate (`test rsp,rsp`) guarding dead junk, wrapped in `pushf/popf` | flag-neutral, no GP clobber |
| `substitute` | `mov rA,rB` → `lea rA,[rB]` or `push rB;pop rA` | flag-neutral; push/pop only on pointer-width regs |
| `jumps` | insert `jmp next` (label-targeted) | jmp is flag-neutral, lands on next insn |
| `callswitch` | `call t` → `push {ret}; jmp t` (**x86 only**) | exact on x86; x64 skipped & counted (see §5.3) |
| `mba` | reg/reg `add/sub/and/or/xor` → MBA identity | flags-dead-proof + **numeric self-check** |
| `constants` | `mov reg,imm` → `mov reg,imm^k; xor reg,k` | flags-dead-proof; key kept in imm32 range |
| `reorder` | swap independent adjacent insns | no RAW/WAR/WAW, no memory, no synthetic |
| `branchfunc` | direct `jmp t` → stack-based indirect transfer | x86 `push{t};ret`; x64 `push rax;mov rax,{t};xchg rax,[rsp];ret` (reg/flag-neutral) |
| `antidisasm` | `jmp over; .byte <decoy>; over:` | junk strictly between jump and target → provably dead |
| `scatter` | split into basic blocks, shuffle order | every edge is a label; fall-throughs get explicit `jmp`; trailing fall-through pinned |
| `stacknoise` | balanced `lea rsp,[rsp±N]` | net-zero, flag-neutral |

`build_passes(level)` orders rewrites-of-real-instructions first (metadata
intact), then synthetic insertion. `Mutator` is the standalone engine;
`python -m codescrambler.mutation in out --level 70 --seed N`.

### 5.3 Open items (documented, low-risk)
- **x64 callswitch**: the return address is a 64-bit absolute that can't be
  `push`-ed as an immediate without a scratch register whose liveness we can't
  always prove at a call site. Implement with a proven-dead scratch (or a
  `lea rip`-relative + `push`) when liveness allows; the pass already counts
  skipped x64 calls.
- **Advanced passes not yet shipped** (deliberately, to avoid shipping
  unverifiable rewrites): full control-flow flattening, per-string inline
  encryption, register renaming, per-build entry-stub randomization. (Anti-
  disassembly, block scattering and branch functions are now shipped as
  `antidisasm`, `scatter`, `branchfunc`; the CFG model is `core/cfg.py`.) Notes
  for the trickiest:
  - *flatten*: the block model (`core/cfg.py`) and scattering are done; full
    flattening additionally needs a **persistent state slot** that survives every
    dispatcher trip — a writable in-image slot (RWX code section + RIP-relative on
    x64, or a reloc'd absolute on x86). That's runtime-critical, hence gated.
  - *regrename*: requires full register liveness (extend `analysis.py` to a
    proper backward dataflow) before it is safe.
  - *entry-stub randomization*: must change the entry to a synthetic stub that
    jumps to the real entry; easiest via a writer post-hook (like protect),
    not as an IR pass, because the entry is resolved from the VA map.

---

## 6. Virtualization engine (`codescrambler/vm`)

### 6.1 Model
A **register VM** whose virtual registers mirror the native GP registers: at VM
entry natives are copied into a context array, bytecode operates on it, at exit
it is copied back. Flags are not modeled → lifting requires flags dead (same
discipline as MBA). Stack pointer is **never** virtualized.

### 6.2 Pieces & maturity
| module | role | maturity |
|--------|------|----------|
| `isa.py` | `VMOp`, `VMInstr`, `VMProgram`, **reference `simulate()`** | verified |
| `randomizer.py` | per-build opcode bytes, key, handler order, reg→slot map | verified |
| `bytecode.py` | encode + rolling-XOR encrypt + decode; `verify_roundtrip` | verified (round-trips) |
| `lifter.py` | native run → `VMProgram`, **numeric self-check** vs native | verified (self-check passes) |
| `interpreter.py` | emit dispatcher+handlers as asm, compile with keystone | **assembles**; runtime unverified |
| `virtualizer.py` | `VirtualizePass`, `LiftReport`, standalone `Virtualizer` | report verified; commit gated |

Supported lift subset today: `mov reg,reg`, `mov reg,imm`,
`add/sub/and/or/xor reg,reg` on non-stack pointer-width registers, in
straight-line runs that don't cross a label and whose flags are dead after the
run. `coverage→1.0` lifts as much of that subset as possible; everything else is
recorded in `LiftReport.skipped` with a reason.

### 6.3 Interpreter ABI (inline-pointer)
```
call vm_dispatch
.quad <bytecode_va>      ; 8-byte pointer the interpreter consumes
<native continuation>    ; ret lands here
```
The interpreter: reserves a 128-byte context on the stack; copies each captured
GP register (not rsp) into its profile slot via `mov [rsp+slot*8], reg` (reads
only → originals preserved); reads the inline pointer and advances the return
address past it; runs a fetch/decrypt/dispatch loop; on `EXIT` restores all
slots to registers and `ret`s. **x64 only** (x86 generator raises
`NotImplementedError`; `VirtualizePass` reports x86 as unsupported and rewrites
nothing — safe).

### 6.4 Commit modes
- `commit=False` (default): produces bytecode + interpreter + report into
  `program.metadata["vm"]` **without rewriting native code** → rebuilt binary
  still runs. This is the safe development/coverage mode.
- `commit=True` (opt-in): also stashes commit artifacts in
  `program.metadata["vm_commit"]` for write-time integration. **Native-code
  replacement + section insertion are not yet wired into the writer** — see the
  contract below.

### 6.5 Continuation: wiring `commit=True` into the writer
The hard part is cross-section label resolution: the call-stub lives in the main
code blob but targets the interpreter section, and embeds a pointer to the
bytecode section. Recommended approach (reserve VAs *before* assembling main
code so the stub can use absolute targets the assembler resolves):
1. Add a VM writer hook ordering change: VAs for the interpreter and bytecode
   sections must be reserved before `_assemble_code()`. Either (a) expose
   `writer.reserve_section(size) -> rva` and call it from a *pre*-assembly hook,
   or (b) give the writer a "vm plan" it consumes at the top of `write()`.
2. For each lifted run, replace its instructions in the IR with a stub:
   - `synth_branch("call", "<interpreter_entry_label>")` **or** a synthetic
     `call <abs_interpreter_va>` (abs VA known from step 1),
   - an 8-byte data instruction holding the bytecode VA (model as an
     `Instruction` with `raw = struct.pack("<Q", bytecode_va)` and
     `mnemonic=".byte"`; the assembler emits raw bytes for those).
   Keep the original run's `label` on the stub's first instruction.
3. Add the interpreter section (generated with `base_va = image_base + its_rva`)
   and the bytecode section (concatenated per-run blobs; the stub pointer points
   at each run's offset). Mark interpreter RX, bytecode R.
4. Because the interpreter is PIC-ish but uses absolute slot math on the stack
   (not absolute code addresses), it needs no relocations. The stub's
   `call`/`.quad` pointer to bytecode is absolute → **add a base relocation**
   for that 8-byte pointer (use `reloc.build_reloc_blocks` with a `DIR64`
   entry), or make the stub compute the bytecode VA PIC-style like the protect
   stub does (preferred; then no new reloc needed).
5. Validate on a Windows VM: start tiny (one lifted `add reg,reg`), confirm
   identical behavior, then widen coverage. The `LiftReport` and the assembled
   `interpreter.listing` are your debugging aids.

---

## 7. Protection engine (`codescrambler/protect`)

### 7.1 What it does (verified off-target)
Encrypts safe non-executable sections at rest and prepends a runtime decryptor
stub (new entry) that restores them in place, then jumps to the real (moved)
entry. Ciphers self-test and round-trip across the full byte range; the stub
assembles with correct anchor-relative deltas.

- `ciphers.py`: `xor_rolling`, `add_rolling`, each with a Python `encrypt` and a
  matching x64 `decrypt_asm`, kept side by side; `build_cipher` randomizes
  key+stride and self-tests. Add a cipher by subclassing `Cipher`.
- `stub.py`: PIC stub. Locates itself with `call/pop`, decrypts each section by
  anchor-relative `lea`, then `jmp` to OEP. Computes the `next:` anchor RVA by
  assembling the fixed prologue to measure its length (no magic offsets).
- `sections.py`: `SectionProtector.attach(writer)` registers a post-hook that
  selects targets, encrypts their on-disk bytes, marks them writable (so the
  loader maps them writable and the stub can restore in place), appends the stub
  as a new code section, and redirects the entry.

### 7.2 Safety-first selection (why a section may be skipped)
A section is **skipped** if it overlaps any data directory
(imports/IAT/TLS/resources/reloc/exception/loadcfg/…) **or** contains any base
relocation target, because the loader consumes those bytes *before* the stub
runs (and applies relocations to encrypted pointers → corruption). `mode=data`
further restricts to writable/`.data`-like sections; `mode=all` takes every safe
non-exec section. This is conservative on purpose: a protected binary always
still runs. Consequence: on heavily-relocated binaries, few sections may
qualify.

### 7.3 Open items
- **Wider coverage**: to protect sections the loader touches, switch to a stub
  that (a) runs, (b) re-applies relocations *after* decrypt, or operate on a
  copy and use `VirtualProtect`. Requires a runtime import of `VirtualProtect`
  (add a tiny import or resolve via PEB walk) — on-target work.
- **Stub assumption**: the original entry must not depend on a specific initial
  `rax` (true for standard CRT entry points). If you target unusual entries,
  extend the stub to also restore `rax` (stash OEP elsewhere, e.g. a scratch
  slot in the stub's own section, and `jmp` through it).
- **x64 only** stub today; an x86 variant is a direct port (32-bit regs,
  `pushfd`, `call/pop` anchor).

---

## 7.5 Hardening engine (`codescrambler/harden`)

Preventive + tamperproofing transforms — the *preventive transformation* and
*tamperproofing* pillars of Collberg & Nagra.

### 7.5.1 Anti-debugging — `AntiDebugPass` (IMPLEMENTED & VERIFIED)
An IR pass that reads the PEB `BeingDebugged` byte with no imports
(x64 `gs:[0x60]`, x86 `fs:[0x30]`, both `+0x02`), and runs a configurable
response (`ud2`/`int3`/`hlt`, default `ud2`) if a debugger is present. The check
saves/restores the one register it uses and the flags, so it is
register/flag-neutral for the surrounding code. It is spliced in right after the
entry instruction (so it runs at the very start). If the entry instruction is a
terminator it is skipped and reported; for guaranteed-first execution under any
entry shape, use the entry-stub hook approach (see §7.3 open items). Verified:
assembles on x64 and x86.

### 7.5.2 Static watermarking — `Watermark` / `extract_watermark` (IMPLEMENTED & VERIFIED)
Embeds a hidden identifier as a data section (`.csmark`) via a writer post-hook;
format `"CSWM" | key | length | xor(payload)`. `extract_watermark(path)` recovers
it from the file. Adding a benign data section cannot affect execution, so this
is fully committed (not gated). Verified: encode→decode round-trip. A
tamper/collusion-resistant *dynamic* watermark (CT-style graph in heap state)
is the documented next step.

### 7.5.3 Tamperproofing — checksum guard (BUILDING BLOCKS; wiring gated)
`checksum()` is a 32-bit FNV-1a with a self-test; `GuardGenerator` emits a
position-independent guard (`call/pop` anchor → hash loop → compare → response)
that hashes a code range at runtime and fires the response on mismatch. Verified:
checksum self-test, guard assembles. **Gated:** inserting guards and patching the
expected value at write time, because the checksummed range must exclude the
guard's own patched immediate (and ideally guards should cross-check each other).
Continuation contract: after `_assemble_code()`, choose a stable range, compute
`checksum(range_bytes)`, generate the guard with that `expected`, append it as RX,
and (optionally) chain it ahead of the entry like the protect stub. This mirrors
the VM-commit maturity (§6.5).

### 7.5.5 Anti-VM / anti-emulation — `AntiVMPass` (IMPLEMENTED & VERIFIED)
An IR pass that detects a hypervisor via `CPUID` leaf 1 ECX bit 31
(hypervisor-present). Self-contained and register/flag-neutral (saves/restores the
four `CPUID`-clobbered registers + flags); runs a configurable response (default
`ud2`) inside a VM, falls through otherwise. Inserted after the entry instruction
(same terminator caveat as anti-debug). Opt-in (`--anti-vm` / `Config.anti_vm`)
because legitimate users may run in VMs. Verified: assembles on x64 and x86.

### 7.5.4 Anti-(automated/AI/LLM)-analysis deterrent — `LlmDeterrent` (IMPLEMENTED & VERIFIED)
Reverse engineering increasingly means pasting a binary, its `strings` dump, or a
disassembly listing into an LLM. `LlmDeterrent` embeds a readable ASCII **notice**
(its own section, randomized innocuous name) instructing automated/AI/LLM readers
to refuse disassembly/decompilation/decryption. `build_notice()` builds the blob
(magic + configurable, repeatable text); `extract_notice(path)` recovers it.
Adding a benign readable section cannot affect execution, so this is fully
committed (verified by embed/extract round-trip). **It is a deterrent layered on
top of the real obfuscation — explicitly *not* a substitute for it**, and it
cannot force a compliant tool to obey.

---

## 8. Orchestration, CLI, emit modes (`engine.py`, `cli.py`, `config.py`)

- `Config`: `mutation` (0–100), `virtualization` (0–100),
  `encrypt_sections` (`none|data|all`), `emit` (`binary|analysis`), `seed`,
  `anti_debug` (bool), `anti_vm` (bool), `watermark` (optional str),
  `llm_deterrent` (bool). The percent knobs expose `mutation_level` /
  `virtualization_coverage` fractions.
- `Engine`: owns the RNG, composes the pipeline (`build_default_pipeline`),
  runs passes, emits either a rebuilt **binary** or an **analysis** JSON dump
  (arch, sections, per-pass reports — great for inspecting coverage without
  producing a PE).
- `cli.py`: the single, small flag-based interface (`__main__.py` makes
  `python -m codescrambler` work).
- Per-engine CLIs: `python -m codescrambler.mutation`, `python -m codescrambler.vm`.

---

## 9. Correctness invariants (the contract every change must keep)

1. **Symbolic control flow.** Never hardcode a displacement; use `branch_label`
   / `label_refs` and let the assembler resolve after layout.
2. **Flag safety.** Don't clobber flags unless `flags_dead_after` proves them
   dead, or you save/restore with `pushf/popf` *and* don't need the produced
   flags.
3. **Register safety.** Don't clobber a register unless proven dead or
   save/restore it (balanced `push/pop`, pointer-width only).
4. **No memory-operand assumptions.** Passes that need aliasing guarantees skip
   memory operands.
5. **Stack pointer is sacred.** Never virtualize or net-change `rsp`/`esp`.
6. **Self-check generative math.** MBA, constant unfolding, the lifter and the
   ciphers all verify their output numerically before committing.
7. **All randomness from `Rng`.** No bare `random` in transform code paths
   (the self-check checkers use a local `random.Random` purely for verification,
   which is fine).
8. **Conservative by default.** When safety can't be proven, skip and count it —
   never miscompile.

---

## 10. Maturity matrix (quick reference)

| Area | Status |
|------|--------|
| core (rng, ir, disasm, asm, registry) | implemented, exercised |
| pe load/write/reloc/fidelity | implemented; zero-transform rebuild exercised in memory; on-target execution test = yours |
| mutation passes (12) | implemented; in-memory assemble + numeric self-checks pass |
| core/cfg.py (basic-block model) | implemented & verified (lossless partition) |
| vm: isa/randomizer/bytecode/lifter | implemented & verified off-target |
| vm: interpreter generator | assembles to valid machine code; **runtime unverified** |
| vm: commit (native replacement) | scaffolded; **writer integration pending** (§6.5) |
| protect: ciphers/stub/selection | implemented; ciphers+stub verified off-target; **runtime unverified** |
| harden: anti-debug | implemented; assembles x86/x64; runtime = yours |
| harden: static watermark | implemented & verified (embed/extract round-trip); fully committed |
| harden: tamper checksum + guard | building blocks verified; **guard insertion/patching gated** (§7.5.3) |
| harden: anti-LLM deterrent | implemented & verified (embed/extract round-trip); fully committed |
| harden: anti-VM (CPUID) | implemented; assembles x86/x64; runtime = yours |
| CLI / engine / emit modes | implemented |
| tests harness | 30 in-memory tests pass; on-target suites = yours (§11) |

---

## 11. Testing (run on your machine — none run here by request)

`tests/` holds `pe_builder.py` (programmatically builds minimal PE32/PE32+ for
fixtures) and `conftest.py` (path setup). Recommended suites to add/run (see
README §Testing):
1. **Determinism**: same seed → identical output bytes; different seed →
   different output.
2. **Standalone imports**: each engine importable without the others.
3. **In-memory pass correctness**: decode → pass → reassemble (already proven
   ad-hoc; fold into pytest).
4. **VM**: `bytecode.verify_roundtrip`, lifter self-check, interpreter assembles.
5. **Ciphers**: encrypt/decrypt round-trip over `bytes(range(256))`.
6. **Fidelity corpus** (on-target): build → run → compare behavior on real,
   safe binaries (e.g. simple console exes) across mutation/virtualization/
   encryption settings.

When you test binaries, do it on an isolated VM — obfuscated output can trip AV
heuristics even when benign.

---

## 12. If something breaks on the test machine — triage map

- **Rebuilt EXE won't load / bad image** → `pe/writer.py` header patching or
  `_ensure_header_room` (not enough header padding to add sections). Check
  SizeOfImage, section count, section table offsets.
- **Crashes at original code** → relocations (`pe/reloc.py`) or directory
  retargeting (`pe/fidelity.py`); verify the VA map covers the faulting RVA.
- **Crashes after a mutated region** → a pass violated an invariant in §9;
  bisect by disabling passes (`build_passes` order) or lowering `--mutation`.
- **Crashes only with `--virtualization` + commit** → expected until §6.5 is
  done and validated; use `commit=False` to confirm the rest is fine.
- **Crashes only with `--encrypt-sections`** → a selected section was actually
  loader-consumed; tighten `protect/sections.py` selection or check the stub
  (`protect/stub.py`) anchor math / writable marking.
- **Determinism broken** → a transform used `random` instead of the passed
  `Rng`.
- **`--anti-debug` did nothing** → the entry instruction was a terminator (the
  pass reports `entry_is_terminator`); use the entry-stub approach.

---

## 13. Coverage vs. *Surreptitious Software* (Collberg & Nagra) — gap analysis

The book organizes software protection into obfuscation, tamperproofing,
watermarking, birthmarking, and (hardware-assisted) anti-piracy. This is an
honest map of what CodeScrambler does, what it partially does, and what is left.

### Implemented
| Book technique (chapter area) | Here |
|-------------------------------|------|
| Control: opaque predicates | `mutation.opaque` |
| Control: dead/irrelevant code | `mutation.junk`, `mutation.stacknoise` |
| Control: ordering (statement reorder) | `mutation.reorder` |
| Control: table interpretation (**virtualization**) | `vm.*` |
| Control: indirection (jumps/calls) | `mutation.jumps`, `mutation.callswitch` |
| Control: block splitting / scattering | `mutation.scatter` (+ `core/cfg.py`) |
| Control: branch functions / indirect dispatch | `mutation.branchfunc` |
| Data: encoding of computations (**MBA**) | `mutation.mba` |
| Data: constant encoding | `mutation.constants` |
| Data: static-data-to-procedure / packing (sections) | `protect.*` (encrypt + runtime stub) |
| Instruction substitution | `mutation.substitute` |
| Preventive: anti-disassembly (junk bytes) | `mutation.antidisasm` |
| Preventive: anti-debugging (PEB + NtGlobalFlag) | `harden.antidebug` |
| Preventive: anti-VM / anti-emulation (CPUID) | `harden.antivm` |
| Preventive: anti-(automated/AI/LLM) analysis | `harden.llm_guard` (deterrent notice) |
| Tamperproofing: checksum guards + response | `harden.tamper` (primitive + generator) |
| Watermarking: static mark | `harden.watermark` |
| Diversity: **metamorphic** body rewriting | `mutation.*` (rewrites real instructions) |
| Diversity: **polymorphic** wrapping | core `Rng` + randomized VM/ciphers/section names |
| Dynamic (limited): runtime code rewrite | `protect` decryptor stub rewrites memory at start |

### Partial / gated (designed, not fully wired)
- **Tamperproofing guard insertion + expected-value patching** — building blocks
  done; write-time wiring gated (§7.5.3).
- **VM native-code replacement (commit)** — artifacts done; writer integration
  gated (§6.5).
- **Code packing of executable sections** — we encrypt non-exec sections only;
  encrypting code needs a runtime `VirtualProtect`/reloc-aware stub (§7.3).

### Skipped — candidate roadmap (and why)
| Book technique | Why skipped / how to add |
|----------------|--------------------------|
| Control-flow flattening (Wang) | CFG model (`core/cfg.py`) + scattering shipped; full flattening needs a persistent state slot (RWX/reloc'd) — runtime-critical, gated |
| Register renaming/reassignment | needs full backward register liveness (extend `analysis.py`) |
| Function inlining / outlining / cloning / interleaving (abstraction) | needs call-graph + boundary detection; hard on stripped binaries |
| Per-string inline encryption + decode stubs | needs reliable string-reference detection; `protect` covers data-at-rest meanwhile |
| Oblivious hashing (tamperproofing) | weave hash of computed values into normal results; needs dataflow |
| Dynamic / CT (Collberg-Thomborson) watermarking | encode a graph in heap structures at runtime; we ship the static mark only |
| Runtime metamorphism (self-rewriting on execute) | we are *static* metamorphic (build-time variants); a runtime rewriter needs an on-target stub + reloc/permission handling |
| White-box cryptography | embed keys in lookup tables (table-network); large, self-contained subproject |
| Birthmarking | an *identification/analysis* technique, not protection; out of scope |
| Hardware anti-piracy (dongles/TPM/node-lock) | requires external hardware/OS services; out of scope |

### "...and more" beyond the book's core catalog
- Build-time **equivalence self-checks** (MBA, lifter, ciphers) so generative
  transforms can't silently miscompile.
- **Conservative liveness gating** so every transform degrades to a no-op rather
  than emit wrong code.
- Strong, single-source **polymorphism/reproducibility** via one seeded RNG.
