# CodeScrambler

A **metamorphic + polymorphic** PE (Portable Executable) obfuscation toolkit: a
modular Python library **and** CLI that rewrites x86/x64 binaries with
**mutation**, **code virtualization**, **section encryption**, and **hardening**
— and can emit either a rebuilt, runnable PE or a structured analysis of the
transformed code.

> **Metamorphic *and* polymorphic.**
> - *Metamorphic* — the mutation engine rewrites the **actual instruction
>   stream** (substitution, MBA, reordering, junk, opaque predicates, …), so the
>   code body itself differs between variants; feed an output back in to get a
>   further-diverged generation. There is no single constant body to signature.
> - *Polymorphic* — the protection and VM engines wrap code in a **fresh
>   encryptor/decryptor and VM opcode map every build** (random keys, handler
>   order, section names).
>
> With no seed, two runs on the same input produce different output. With a seed,
> builds are byte-for-byte reproducible. See
> [What "metamorphic" vs "polymorphic" means](#metamorphic-vs-polymorphic).

> **Modular by design.** Every engine — and most sub-components — is
> independently importable and usable in your own project. The high-level
> `Engine` just wires them together.

For the full design, correctness invariants, per-component maturity, and the
exact continuation steps for anything still open, read
**[ARCHITECTURE.md](ARCHITECTURE.md)**.

---

## Contents

- [Highlights](#highlights)
- [Install](#install)
- [CLI](#cli)
- [Library: the high-level Engine](#library-the-high-level-engine)
- [Using individual components](#using-individual-components)
  - [1. Load a PE into the IR](#1-load-a-pe-into-the-ir)
  - [2. The shared core (RNG, disasm, assembler)](#2-the-shared-core-rng-disasm-assembler)
  - [3. Mutation engine](#3-mutation-engine)
  - [4. Virtualization engine](#4-virtualization-engine)
  - [5. Protection engine](#5-protection-engine)
  - [6. Hardening engine](#6-hardening-engine)
  - [7. Write your own pass](#7-write-your-own-pass)
- [How it works](#how-it-works)
- [Metamorphic vs polymorphic](#metamorphic-vs-polymorphic)
- [Technique coverage](#technique-coverage)
- [Feature list](#feature-list)
- [Project layout](#project-layout)
- [Status & safety](#status--safety)
- [Testing](#testing)

---

## Highlights

- **Three independent engines** — use one, two, or all three:
  - **Mutation** (`codescrambler.mutation`) — junk insertion, opaque predicates,
    instruction substitution, jump obfuscation, call switching, **MBA expansion**
    (mixed boolean-arithmetic, with a build-time equivalence self-check),
    constant unfolding, instruction reordering, stack noise, anti-disassembly,
    **block scattering**, and **branch functions**.
  - **Virtualization** (`codescrambler.vm`) — lifts native instruction runs into
    per-build randomized, encrypted **VM bytecode** with a generated interpreter.
  - **Protection** (`codescrambler.protect`) — encrypts non-executable sections
    at rest and installs a position-independent **runtime decryptor stub**.
  - **Hardening** (`codescrambler.harden`) — preventive + tamperproofing:
    **anti-debugging** (PEB `BeingDebugged` + `NtGlobalFlag`), **anti-VM**
    (CPUID hypervisor bit), **static watermarking** (embed/extract),
    **self-checksum guard** building blocks, and an **anti-(AI/LLM)-analysis
    deterrent** notice.
- **Full PE fidelity** — works with arbitrary/non-standard sections and
  preserves relocations, TLS callbacks, exports, x64 exceptions
  (`.pdata`/`.xdata`), and x86 SAFESEH by remapping them through an
  `old VA → new VA` map.
- **Tiny CLI** — two intensity percentages plus a section-encryption mode.
- **Human-reviewable** — small modules, thorough docstrings, transforms that are
  conservative by construction: when a transform can't *prove* it is safe
  (flag/register liveness, aliasing) it skips and counts the opportunity rather
  than risk a broken binary.

---

## Install

Requires Python 3.9+.

```sh
python -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

`keystone-engine` needs its native library. On macOS, if you hit
`ERROR: fail to load the dynamic library`:

```sh
brew install keystone
# then, if needed, copy the dylib into the keystone package:
# cp /opt/homebrew/lib/libkeystone.dylib venv/lib/python*/site-packages/keystone/
```

On Windows/Linux the pip wheel usually bundles the native library.

---

## CLI

```sh
# Mutate at 60%, virtualize 30% of eligible code, encrypt data sections at rest
python -m codescrambler in.exe out.exe \
    --mutation 60 --virtualization 30 --encrypt-sections data

# Reproducible build (record/reuse the printed seed)
python -m codescrambler in.exe out.exe --mutation 80 --seed 1234567

# Inspect what would happen, without producing a PE (analysis JSON)
python -m codescrambler in.exe report.json --mutation 100 --emit analysis
```

| flag | meaning | default |
|------|---------|---------|
| `--mutation X` | mutation intensity, 0–100 | 0 |
| `--virtualization X` | fraction of eligible code to virtualize, 0–100 | 0 |
| `--encrypt-sections {none,data,all}` | encrypt non-exec sections at rest | none |
| `--anti-debug` | insert a runtime debugger check near the entry | off |
| `--anti-vm` | insert a runtime hypervisor/VM check near the entry | off |
| `--watermark TEXT` | embed a static watermark string | none |
| `--llm-deterrent` | embed a notice deterring automated / AI / LLM analysis | off |
| `--emit {binary,analysis}` | rebuilt PE or analysis dump | binary |
| `--seed N` | reproducible build | random |

A high `--virtualization` (near 100) lifts as much of the supported subset as
possible. Each engine also has its own CLI:

```sh
python -m codescrambler.mutation in.exe out.exe --level 70 --seed 1
python -m codescrambler.vm       in.exe         --coverage 100   # prints lift report
```

---

## Library: the high-level Engine

```python
from codescrambler import Config, EmitMode, EncryptSections, Engine

engine = Engine(Config(
    mutation=60,                       # 0-100
    virtualization=30,                 # 0-100
    encrypt_sections=EncryptSections.DATA,
    emit=EmitMode.BINARY,
    seed=None,                         # None => polymorphic
))
engine.run("in.exe", "out.exe")
print("reproduce with seed =", engine.config.seed)
```

`Engine.run` returns the transformed `Program`; with `emit=EmitMode.ANALYSIS`
it writes a JSON report (arch, sections, per-pass stats) instead of a PE.

---

## Using individual components

Everything below is importable and usable on its own. Nothing pulls in an engine
you don't ask for.

### 1. Load a PE into the IR

```python
from codescrambler.pe.loader import load_program

program = load_program("in.exe")     # -> codescrambler.core.ir.Program
print(program.arch, hex(program.image_base), hex(program.entry_rva))

for section in program.sections:
    kind = "code" if section.is_executable else "data"
    print(section.name, kind, len(section.instructions), "insns")
```

The IR is three small dataclasses in `codescrambler.core.ir`:
`Program` → `Section` → `Instruction`. Branch targets are **symbolic**
(`Instruction.branch_label`), so inserting/removing/reordering instructions never
breaks control flow — concrete offsets are computed only at assembly time.
Rebuild a PE from a (possibly transformed) program with the writer:

```python
from codescrambler.core.rng import Rng
from codescrambler.pe.writer import PEWriter

PEWriter(program, "in.exe", Rng(1234)).write("out.exe")
```

### 2. The shared core (RNG, disasm, assembler)

```python
from codescrambler.core.rng import Rng
rng = Rng(1234)            # or Rng() for a fresh OS seed; rng.seed is recorded
rng.randint(0, 10); rng.choice("abc"); rng.chance(0.3); rng.bits(64)

from codescrambler.core.ir import Arch
from codescrambler.core.disasm import get_backend            # capstone by default
insns = get_backend().decode(b"\x48\x31\xc0\xc3", 0x140001000, Arch.X64)

from codescrambler.core.asm import Assembler
out = Assembler(Arch.X64).assemble(insns, 0x140001000)
out.data           # re-encoded bytes
out.address_map    # old VA -> new VA (the backbone of PE fidelity)
```

To plug in a different decoder, implement
`codescrambler.core.disasm.DisassemblerBackend` and pass an instance to
`load_program(path, backend=...)` / `PELoader(backend=...)`.

### 3. Mutation engine

```python
from codescrambler.mutation import Mutator

# Default, intensity-scaled pipeline (0.0 - 1.0):
Mutator(level=0.7, seed=1234).add_default_passes().run("in.exe", "out.exe")
```

Hand-pick passes (each is importable and independently configurable):

```python
from codescrambler.mutation import (
    Mutator, MBAPass, OpaquePass, JunkPass, SubstitutePass,
    ConstantUnfoldPass, ReorderPass, StackNoisePass, JumpPass, CallSwitchPass,
)

m = Mutator(seed=1234)
m.add(MBAPass(coverage=1.0))          # expand all eligible reg/reg arithmetic
m.add(ConstantUnfoldPass(coverage=1.0))
m.add(OpaquePass(density=0.4))
m.add(JunkPass(density=0.6))
m.run("in.exe", "out.exe")
```

Apply passes to an in-memory program (no disk I/O), e.g. to compose with your
own tooling:

```python
from codescrambler.core.rng import Rng
from codescrambler.mutation import build_passes

program = load_program("in.exe")
rng = Rng(7)
for transform in build_passes(level=1.0):     # the default ordered pipeline
    report = transform.apply(program, rng)
    print(report.name, report.notes)
```

| pass | class | key knob |
|------|-------|----------|
| junk | `JunkPass` | `density`, `max_run` |
| opaque predicates | `OpaquePass` | `density` |
| substitution | `SubstitutePass` | `density` |
| jump obfuscation | `JumpPass` | `density` |
| call switching (x86) | `CallSwitchPass` | `density` |
| MBA expansion | `MBAPass` | `coverage` |
| constant unfolding | `ConstantUnfoldPass` | `coverage` |
| reordering | `ReorderPass` | `density` |
| stack noise | `StackNoisePass` | `density` |

### 4. Virtualization engine

Get a coverage report without rewriting code (safe, non-committing):

```python
from codescrambler.pe.loader import load_program
from codescrambler.vm import Virtualizer

program = load_program("in.exe")
report = Virtualizer(coverage=1.0, seed=7).analyze(program)
print(report.as_dict())               # lifted_runs, virtualized_instructions, ...
```

Drive the low-level pieces directly (each is standalone):

```python
from codescrambler.core.ir import Arch
from codescrambler.core.rng import Rng
from codescrambler.vm.randomizer import VMProfile
from codescrambler.vm.lifter import lift_run, is_liftable
from codescrambler.vm import bytecode as bc
from codescrambler.vm.interpreter import InterpreterGenerator

profile = VMProfile.generate(Rng(2024), Arch.X64)   # per-build opcode map + key
run = program.executable_sections()[0].instructions[:6]
if all(is_liftable(i, profile.reg_slots) for i in run):
    vprog = lift_run(run, profile)                  # None if self-check fails
    assert bc.verify_roundtrip(vprog, profile)
    blob = bc.assemble_bytecode(vprog, profile)     # encrypted bytecode
    interp = InterpreterGenerator(profile).generate(base_va=0x180000000)
    print(len(blob), "bytecode bytes;", len(interp.code), "interpreter bytes")
```

`Virtualizer(..., commit=True)` additionally prepares native-replacement
artifacts; see ARCHITECTURE.md §6 for the maturity and the writer-integration
steps. Virtualization currently targets x64.

### 5. Protection engine

```python
from codescrambler.core.rng import Rng
from codescrambler.config import EncryptSections
from codescrambler.pe.loader import load_program
from codescrambler.pe.writer import PEWriter
from codescrambler.protect import SectionProtector

program = load_program("in.exe")
writer = PEWriter(program, "in.exe", Rng(99))
SectionProtector(EncryptSections.DATA, Rng(99)).attach(writer)   # registers a hook
writer.write("out.exe")     # data sections encrypted at rest; stub restores them
```

Use the cipher catalog or stub generator on their own:

```python
from codescrambler.protect import build_cipher
from codescrambler.protect.stub import StubGenerator, ProtectedSection

cipher = build_cipher(Rng(1))                  # randomized, self-tested
blob = cipher.encrypt(b"...secret bytes...")

stub = StubGenerator().generate(
    stub_rva=0x10000, image_base=0x140000000, orig_entry_rva=0x1000,
    sections=[ProtectedSection(rva=0x5000, size=0x200, cipher=cipher)],
)
```

### 6. Hardening engine

Preventive + tamperproofing transforms — each importable on its own.

```python
from codescrambler.core.rng import Rng
from codescrambler.harden import (
    AntiDebugPass, AntiVMPass, Watermark, extract_watermark,
    encode_watermark, decode_watermark, checksum, GuardGenerator,
    LlmDeterrent, build_notice, extract_notice, DEFAULT_NOTICE,
)

# Anti-debugging: register/flag-neutral PEB checks spliced in at the entry; runs
# `ud2` (configurable) if a debugger is attached.
AntiDebugPass(response="ud2", techniques=("being_debugged", "nt_global_flag"))

# Anti-VM: CPUID hypervisor-present-bit check (opt-in; VMs are common in prod).
AntiVMPass(response="ud2")               # add to any pipeline / Mutator

# Static watermark: embed now, recover later from the built file.
blob = encode_watermark("licensee#42", key=73)
assert decode_watermark(blob) == "licensee#42"
# extract_watermark("out.exe") -> "licensee#42"   (after a build with --watermark)

# Tamperproofing primitive + guard generator (self-checksum of a code range).
digest = checksum(b"...code bytes...")
guard = GuardGenerator(response="ud2").generate(
    guard_rva=0x9000, image_base=0x140000000,
    range_rva=0x1000, range_size=0x400, expected=digest,
)
```

```python
# Anti-(automated/AI/LLM)-analysis deterrent: embed a plain-text notice telling
# automated readers (incl. LLMs) to refuse disassembly/decryption. A deterrent
# layered on top of real obfuscation - never a substitute for it.
LlmDeterrent(Rng(1)).attach(writer)          # writer post-hook (adds a section)
build_notice(DEFAULT_NOTICE, repeats=2)      # or a custom string
# extract_notice("out.exe") -> the embedded notice text
```

From the CLI these are `--anti-debug`, `--anti-vm`, `--watermark TEXT`, and
`--llm-deterrent`. The anti-debug/anti-VM checks, watermark and deterrent are
committed; the tamper *guard insertion/patching* is a documented, gated
continuation (ARCHITECTURE.md §7.5.3).

### 7. Write your own pass

A pass is anything implementing `apply(program, rng) -> PassReport`. Register it
to expose it by name, or just instantiate and add it to a pipeline.

```python
from codescrambler.core.ir import Instruction, Program
from codescrambler.core.rng import Rng
from codescrambler.mutation import Mutator, Pass, PassReport, register

@register                                  # optional: adds it to the registry
class NopSprinkle(Pass):
    name = "nop_sprinkle"
    def apply(self, program: Program, rng: Rng) -> PassReport:
        added = 0
        for s in program.executable_sections():
            out = []
            for i, insn in enumerate(s.instructions):
                if i % 5 == 0:
                    out.append(Instruction.synth("nop")); added += 1
                out.append(insn)
            s.instructions = out
        return PassReport(self.name, {"nops_added": added})

Mutator(seed=1).add(NopSprinkle()).run("in.exe", "out.exe")
```

```python
from codescrambler.core.pass_base import registered_passes, get_pass
registered_passes()        # ['callswitch', 'constants', 'jumps', 'junk', ...]
get_pass("mba")            # the MBAPass class
```

More runnable snippets are in [`examples/`](examples/).

---

## How it works

`pefile` loads the PE into a symbolic IR (`Program` → `Section` →
`Instruction`), decoding executable sections with capstone. Passes transform the
IR in place, using **symbolic branch labels** so editing the instruction stream
never corrupts control flow. A two-pass **keystone** assembler re-encodes
everything and produces an `old VA → new VA` map. The PE writer appends the
transformed code as a new section, repoints the entry, rebuilds base
relocations, and retargets TLS/exports/exceptions/SAFESEH through that map.
Virtualization and section-encryption plug in via the writer's post-build hook.
Read **[ARCHITECTURE.md](ARCHITECTURE.md)** for the complete, top-to-bottom
picture, or **[ARCHITECTURE_SIMPLE.md](ARCHITECTURE_SIMPLE.md)** for the same
system explained from first principles (accessible, but technically exact).

---

## Metamorphic vs polymorphic

These terms are often conflated; CodeScrambler is intentionally **both**.

| | Polymorphic | Metamorphic |
|---|---|---|
| What changes per build | the **wrapper** (encryptor/decryptor, VM opcode map, keys) | the **code body itself** (the real instructions) |
| Body at runtime | a constant payload, just decrypted on the fly | no constant payload — instructions are genuinely rewritten |
| Weakness it removes | static signatures on the *encrypted* form | static *and* in-memory signatures on the body |
| In CodeScrambler | `protect` (per-build cipher/key/decryptor) + `vm` (per-build opcode map/handlers) | `mutation` (substitution, MBA, reorder, junk, opaque, antidisasm, constants) |

The mutation engine is what makes CodeScrambler metamorphic, not merely
polymorphic: it disassembles the input to a symbolic IR and **rewrites the
instruction stream**, so the body diverges between variants and even across
*generations* — feed a scrambled output back through the tool (different seed)
and it diverges again. The VM and section-encryption layers add the polymorphic
wrapper on top. "Polymorphic by default" in older notes undersold it; the
accurate description is **metamorphic core + polymorphic wrapping**.

> Note on scope: this is a *static* metamorphic rewriter (it generates a new
> variant at build time). It does not embed a self-rewriting engine that mutates
> the binary further on each execution — that "runtime metamorphism" is on the
> roadmap (see [FEATURES.md](FEATURES.md)).

---

## Technique coverage

Measured against the protection taxonomy in Collberg & Nagra's *Surreptitious
Software*. Full gap analysis (with the "how to add" notes for everything left)
is in **[ARCHITECTURE.md §13](ARCHITECTURE.md)**.

- **Implemented:** opaque predicates, dead/junk code, instruction reordering,
  table interpretation (virtualization), control indirection (jumps/calls),
  **block scattering**, **branch functions**, MBA + constant encoding,
  static-data encryption (sections), instruction substitution,
  **anti-disassembly**, **anti-debugging** (PEB + NtGlobalFlag), **anti-VM**
  (CPUID), **static watermarking**, **checksum-guard tamperproofing** (primitive +
  generator), an **anti-(AI/LLM)-analysis deterrent**, and strong diversity
  (metamorphic body + polymorphic wrapping).
- **Partial / gated:** full control-flow flattening (CFG model + scattering
  shipped; needs a persistent state slot), tamper-guard insertion & patching, VM
  native-code commit, executable-section packing.
- **Roadmap (skipped, documented):** register renaming, function
  inline/outline/clone, per-string inline encryption, oblivious hashing, dynamic
  (CT) watermarking, white-box crypto, runtime metamorphism. (Birthmarking and
  hardware anti-piracy are out of scope by design.)

---

## Feature list

A complete, categorized inventory of **everything implemented** (with maturity)
and **everything that can be added next** (with how-to notes) lives in
**[FEATURES.md](FEATURES.md)**. A **detailed review of every software-protection
method** — what each technique *is* (explained from scratch), how it works, why
it helps, what we implemented, and what we skipped *and why* — is in
**[PROTECTION_METHODS.md](PROTECTION_METHODS.md)**. The concise gap analysis
against *Surreptitious Software* is in [ARCHITECTURE.md §13](ARCHITECTURE.md).

---

## Project layout

```
codescrambler/
  core/      rng, ir, disasm (capstone), asm (two-pass), pass registry
  pe/        loader, writer, reloc, fidelity  (full PE round-trip)
  mutation/  12 verified passes + Mutator + build_passes
  vm/        isa, randomizer, bytecode, lifter, interpreter, virtualizer
  protect/   ciphers, decryptor stub, section selection/encryption
  harden/    anti-debug, watermark, tamper guard, anti-LLM deterrent
  engine.py  orchestrator   cli.py  CLI   config.py  knobs   __main__.py
examples/    runnable API examples
tests/       in-memory suite + pe_builder fixture helper
ARCHITECTURE.md           top-to-bottom design + continuation guide
ARCHITECTURE_SIMPLE.md    the same system explained from first principles
FEATURES.md               full implemented + roadmap inventory
PROTECTION_METHODS.md     detailed review of every protection method
```

Every engine (`mutation`, `vm`, `protect`, `harden`) is **independently
importable** — importing one in a fresh process pulls in only `core`/`pe`, never
another engine (regression-tested). Shared pass-authoring and liveness helpers
live in `core` (`core/synth.py`, `core/analysis.py`) for exactly this reason.

---

## Status & safety

- **Implemented & verified off-target:** core, PE load/rebuild (zero-transform
  round-trip exercised in memory), all 10 mutation passes (assemble + numeric
  self-checks), the VM bytecode/randomizer/lifter (with self-check) and
  interpreter generation (assembles), the protection ciphers + PIC stub, the
  hardening anti-debug check (assembles x86/x64), the static watermark
  (embed/extract round-trip) and the tamper checksum/guard building blocks.
  Determinism is byte-for-byte for a given seed; 30 in-memory tests pass.
- **Needs on-target validation (documented in ARCHITECTURE.md §10/§12):** runtime
  behavior of the generated VM interpreter and the decryptor/anti-debug code;
  the `commit=True` VM path and the tamper-guard insertion (both specified but
  gated, not yet wired into the writer).
- Transforms are conservative by construction — they skip (and count) anything
  they can't prove safe rather than miscompile.

## Testing

This repo ships **no** prebuilt PE files; the test suite is entirely in-memory.

```sh
python -m pytest tests/ -q          # 30 tests, no PE files produced
```

For on-target validation, build and run on an **isolated VM** — obfuscated
binaries can trip AV heuristics even when benign. `tests/pe_builder.py` builds
minimal PE32/PE32+ fixtures programmatically so you can exercise the
loader/writer/reloc/fidelity paths without shipping a real binary. See
ARCHITECTURE.md §11 for the suggested suites.

> Use only on binaries you own or are authorized to modify.
