# CodeScrambler — feature inventory

Two lists: **what is implemented** (with maturity), and **what can be added next**
(with the how-to). Maturity tags:

- **[V]** verified off-target (in-memory tests: assemble / numeric self-check /
  round-trip).
- **[A]** assembles to valid machine code; runtime behavior is yours to validate
  on an isolated VM.
- **[G]** gated: building blocks done, final write-time wiring documented but not
  enabled (so we never ship an unproven runtime rewrite).
- **[C]** committed & safe by construction (cannot change runtime behavior).

Runtime validation of anything that executes is deferred to you by request; no PE
files are produced by this repo.

---

## Implemented

### Core substrate (`codescrambler/core`)
- **[V]** Seeded, reproducible RNG (`rng.Rng`) — single source of all randomness;
  same seed → identical build, no seed → unique build.
- **[V]** Symbolic IR (`ir.py`: `Program`/`Section`/`Instruction`) with branch
  labels, RIP-relative metadata, register + **CPU-flag** liveness, `label_refs`.
- **[V]** Disassembler (`disasm/`, capstone) → IR, plus `DisassemblerBackend` ABC
  as an extension point; handles `.byte` data gracefully.
- **[V]** Two-pass keystone assembler (`asm/`) with fixpoint layout, label
  resolution, RIP-relative rewriting, and an `old VA → new VA` map. Unchanged
  instructions keep original bytes verbatim.
- **[V]** Pass contract + registry (`pass_base.py`).
- **[V]** Shared pass-authoring helpers (`synth.py`: `LabelMaker`,
  `synth_branch`, `synth_labeled`) and conservative liveness (`analysis.py`:
  `flags_dead_after`, `register_dead_after`, `gp_registers`) — in `core` so every
  engine stays independently importable.
- **[V]** Basic-block model (`cfg.py`: `build_blocks`/`flatten_blocks`,
  `BasicBlock`) — foundation for control-flow transforms; lossless partition.
- **[V]** Engine independence: `mutation`, `vm`, `protect`, `harden` each import
  in a fresh process without pulling in the others (regression-tested).

### PE fidelity (`codescrambler/pe`)
- **[V/A]** Loader → IR over **all** executable sections (any name, non-standard
  layouts).
- **[A]** Writer: appends a new code section, redirects the entry point, runs
  post-build hooks; zero-transform rebuild exercised in memory.
- **[A]** Base-relocation read / remap / rebuild (ASLR-safe).
- **[A]** Directory retargeting (`fidelity.py`): TLS callbacks, exports,
  exception tables (`.pdata`/`.xdata`), SAFESEH.

### Mutation engine — *metamorphic* body rewriting (`codescrambler/mutation`)
- **[V]** `junk` — register/flag-preserving filler.
- **[V]** `opaque` — always-true predicate guarding dead code (`pushf/popf`).
- **[V]** `substitute` — `mov`→`lea` / `push;pop` (pointer-width).
- **[V]** `jumps` — insert `jmp next`.
- **[V]** `callswitch` — `call`→`push ret; jmp` (x86).
- **[V]** `mba` — Mixed Boolean-Arithmetic expansion with **numeric self-check**.
- **[V]** `constants` — constant hidden behind XOR mask.
- **[V]** `reorder` — swap independent adjacent instructions.
- **[V]** `antidisasm` — unreachable decoy bytes behind a guaranteed jump
  (defeats linear sweep; provably dead).
- **[V]** `scatter` — split into basic blocks and shuffle order; fall-through
  edges relinked with explicit jumps (built on `core/cfg.py`).
- **[V]** `branchfunc` — direct `jmp` → stack-based indirect transfer (x86 + x64,
  register/flag-neutral).
- **[V]** `stacknoise` — balanced, flag-neutral `lea rsp,[rsp±N]`.
- **[V]** `Mutator` standalone engine + `build_passes(level)` intensity pipeline +
  `python -m codescrambler.mutation`.

### Virtualization engine — *polymorphic* table interpretation (`codescrambler/vm`)
- **[V]** VM ISA + reference `simulate()`.
- **[V]** Per-build randomizer (opcode map, keys, handler order, register slots).
- **[V]** Encrypted bytecode encode/encrypt/decode with verified round-trip.
- **[V]** Lifter (native run → bytecode) with equivalence self-check; refuses
  `rsp`/`esp`.
- **[A]** Interpreter generator (emits dispatcher + handlers as x64 asm).
- **[V/G]** `VirtualizePass` + lift report; **native-code replacement (commit)**
  is **[G]** (writer integration specified, not wired).

### Protection engine — *polymorphic* encryption wrapper (`codescrambler/protect`)
- **[V]** Cipher catalog (`XorRolling`, `AddRolling`) — Python encrypt + matching
  x64 decrypt asm + self-test.
- **[A]** Position-independent runtime decryptor stub (`call/pop` anchor).
- **[A]** Section selection + at-rest encryption of safe non-exec sections +
  writer hook + entry redirect.

### Hardening engine — preventive + tamperproofing (`codescrambler/harden`)
- **[A]** `AntiDebugPass` — import-free PEB checks: `BeingDebugged` +
  `NtGlobalFlag` (selectable via `techniques=`), configurable response, x64/x86.
- **[A]** `AntiVMPass` — `CPUID` hypervisor-present-bit check, configurable
  response, x64/x86.
- **[V/C]** `Watermark` / `extract_watermark` — static watermark embed/extract.
- **[V/G]** `checksum` + `GuardGenerator` — self-checksum guard building blocks;
  guard insertion/patching **[G]**.
- **[V/C]** `LlmDeterrent` / `build_notice` / `extract_notice` —
  anti-(automated/AI/LLM)-analysis notice embedded as a readable section.

### Orchestration & UX
- **[V/A]** `Engine` + `Config`; lazy per-knob engine loading.
- **[V]** CLI: `--mutation`, `--virtualization`, `--encrypt-sections`,
  `--anti-debug`, `--watermark`, `--llm-deterrent`, `--emit`, `--seed`.
- **[V]** Emit modes: rebuilt `binary` or structured `analysis`.
- **[V]** 33 in-memory tests; examples in `examples/`.

---

## Can be added next (roadmap)

### Obfuscation depth (CFG model now shipped in `core/cfg.py`)
- **Control-flow flattening** — basic blocks routed through a dispatcher driven by
  a state variable. CFG model + block scattering are shipped; the remaining piece
  is a persistent state slot (RWX code section / reloc'd absolute) — runtime-
  critical, hence gated.
- **Register renaming/reassignment** — needs full backward register liveness
  (extend `core/analysis.py`).
- **Function inline / outline / clone / interleave** — abstraction-level changes;
  needs a call graph and boundary detection.
- **Loop transformations** (unroll/split/fuse) — needs loop recognition on the CFG.

### Data protection
- **Per-string inline encryption** — locate string references, encrypt at rest,
  decrypt at use with an inline stub.
- **Executable-section packing** — encrypt `.text` and unpack at runtime via a
  reloc-aware, `VirtualProtect`-using stub (extends the protect stub).
- **Stronger ciphers** — block cipher / keystream variants in the cipher catalog.

### Preventive / anti-analysis
- **More anti-VM detectors** — RDTSC timing, VM artifact checks (the CPUID
  hypervisor-bit detector is shipped as `AntiVMPass`).
- **Advanced anti-debugging** — hardware-breakpoint (DR) checks, timing traps,
  self-debugging (PEB `BeingDebugged` + `NtGlobalFlag` are shipped).
- **Entry-stub randomization** — synthesize a randomized entry stub that jumps to
  the real entry (writer post-hook, like protect).
- **Richer LLM/AI deterrents** — scatter notices near each protected section,
  decoy "explanations" that mislead automated summarizers, honeytoken strings.

### Tamperproofing
- **Wire the checksum guard** — choose a stable range, compute `expected`, append
  the guard, optionally chain ahead of entry (complete `harden/tamper.py` [G]).
- **Overlapping / mutually-checking guards** — networks of guards that verify
  each other (Chang-Atallah / Horne).
- **Oblivious hashing** — fold a hash of *computed values* into normal results so
  tampering corrupts output (needs dataflow).

### Watermarking
- **Dynamic / CT (Collberg-Thomborson) watermark** — encode a graph in runtime
  heap structures; recover by tracing a special input.
- **Robustness** — error-correcting / spread-spectrum encoding of the static mark.

### Metamorphism (see README "Metamorphic vs polymorphic")
- **Runtime metamorphism** — embed a self-rewriting stub that re-mutates the body
  on each execution (not just at build time). Highest risk; needs a tiny
  on-target rewriter and careful reloc/permission handling.
- **Generational driver** — a helper that re-runs the pipeline N times with fresh
  seeds to mass-produce divergent variants (the static pipeline already supports
  feeding an output back in).

### Crypto / advanced
- **White-box cryptography** — embed keys inside lookup-table networks.

### Delivery phases (how this was rolled out)
- **Phase 1 — CFG foundation:** `core/cfg.py` basic-block model.
- **Phase 2 — control-flow layout:** `mutation.scatter` (block scattering).
- **Phase 3 — control indirection:** `mutation.branchfunc` (x86 + x64).
- **Phase 4 — anti-VM:** `harden.antivm` (CPUID hypervisor bit).
- **Phase 5 — anti-debug depth:** `harden.antidebug` + NtGlobalFlag technique.
- **Future phases (gated/runtime):** full flattening (state slot), executable
  packing, VM commit, tamper-guard wiring, register renaming, per-string
  encryption, dynamic watermarking, runtime metamorphism, white-box crypto.

### Out of scope by design
- **Birthmarking** — an *identification/analysis* technique, not a protection.
- **Hardware anti-piracy** (dongles, TPM, node-locking) — requires external
  hardware / OS services.
