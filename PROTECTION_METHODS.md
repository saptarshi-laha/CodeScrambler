# Software protection methods — a detailed review

This document explains the **landscape of software protection** from first
principles, then states, for each technique: **what it is**, **how it works**,
**why it helps**, **how an attacker fights back**, and **where CodeScrambler
stands** (implemented / partial / skipped — and *why*). It is written so a reader
who has never seen these techniques can follow, while staying technically exact.

For the terse inventory see [FEATURES.md](FEATURES.md). For the implementation
design see [ARCHITECTURE.md](ARCHITECTURE.md). For a gentle conceptual on-ramp
see [ARCHITECTURE_SIMPLE.md](ARCHITECTURE_SIMPLE.md). The reference frame is
Collberg & Nagra, *Surreptitious Software* (2009), broadened with later
techniques (MBA, modern anti-analysis, anti-AI).

Status legend: **DONE** (implemented & verified off-target), **PARTIAL/GATED**
(building blocks done, final wiring documented but not enabled), **SKIPPED**
(not implemented — with the reason), **OUT OF SCOPE** (doesn't fit a static PE
rewriter).

---

## 0. The threat model (who are we defending against?)

A **defender** ships a compiled program; an **adversary** has the binary and
wants to *understand*, *modify*, *copy*, or *re-license* it. The adversary's
toolkit: **static analysis** (disassemblers like IDA/Ghidra, decompilers, string
scanners, and increasingly **LLMs**), **dynamic analysis** (debuggers, emulators,
sandboxes, instrumentation like Pin/Frida), and **tampering** (patching bytes to
remove checks).

No software-only protection is unbreakable against a determined attacker with
physical access to the binary — the goal is to **raise cost and time** past the
attacker's budget. Protections are therefore layered: obfuscation slows
understanding, anti-analysis slows tooling, tamperproofing detects edits,
watermarking attributes leaks, and diversity prevents one break from scaling to
all copies.

The five pillars:
1. **Obfuscation** — make the code hard to *understand*.
2. **Encryption / packing** — make the code hard to *see* until runtime.
3. **Preventive / anti-analysis** — make the *tools* fail or refuse.
4. **Tamperproofing** — *detect and react* to modification.
5. **Watermarking / fingerprinting** — *attribute* a copy to a source.

Plus **diversity** (polymorphism + metamorphism) cutting across all five.

---

## 1. Diversity — polymorphism and metamorphism

### 1.1 Polymorphism
**What it is.** Producing many functionally identical variants that *look*
different by changing an outer, reversible layer — typically encryption with a
fresh key (and often a slightly mutated decryptor) per variant.
**How it works.** The payload is stored encrypted; a small decryptor restores it
at runtime. Change the key/cipher each build and the on-disk bytes change, but
the decrypted body is constant.
**Why it helps.** Defeats static byte-signatures on the *encrypted* form; forces
per-sample work.
**Attacker's counter.** Let it decrypt (run it / emulate the stub), then
signature the now-constant body.
**In CodeScrambler: DONE.** The protection engine (`protect`) uses a per-build
random cipher + key + position-independent decryptor stub; the VM engine (`vm`)
randomizes the opcode map, handler order and bytecode keys per build. All driven
by one seeded RNG (`core.rng`).

### 1.2 Metamorphism
**What it is.** Producing variants by rewriting the **actual code body** —
different instructions, same behavior — so there is *no* constant decrypted
payload to signature.
**How it works.** Disassemble to a neutral representation, apply
semantics-preserving rewrites (substitution, reordering, junk, expansion), and
re-emit. A true metamorphic engine can re-apply to its own output, yielding new
generations.
**Why it helps.** Defeats both static *and* in-memory signatures; there is no
"unwrap to a known body" step.
**Attacker's counter.** Normalize/simplify (optimizing deobfuscators, symbolic
execution) to a canonical form, then compare.
**In CodeScrambler: DONE (build-time).** The mutation engine (`mutation`)
rewrites the real instruction stream; feeding an output back through the tool
diverges it further. *Runtime* metamorphism (a stub that re-mutates on each
execution) is **SKIPPED** for now — see §9.

---

## 2. Code obfuscation

### 2.1 Layout / lexical obfuscation
**What it is.** Stripping or scrambling human-friendly names, comments, and
formatting (identifiers → `a`, `b`, `c`).
**How it works.** Operates on *source* or rich metadata (e.g. .NET/Java symbols).
**Why it helps.** Removes semantic hints the author left behind.
**In CodeScrambler: OUT OF SCOPE (mostly).** We rewrite *native* PE machine
code, where symbol names are usually already gone. (Stripping leftover debug
symbol directories is a possible small add — see §10.)

### 2.2 Data obfuscation
Hiding *what the data is* and *how it is stored*.

- **Constant / integer encoding.** Replace a literal `N` with an expression that
  computes `N` at runtime (e.g. `N = (x ^ k) ...`).
  *Why:* the constant no longer appears in the binary.
  **In CodeScrambler: DONE** — `mutation.constants` rewrites `mov reg, imm` into
  `mov reg, imm^k; xor reg, k` (key kept encodable).
- **Mixed Boolean-Arithmetic (MBA).** Rewrite arithmetic/bitwise ops as tangled
  but provably-equal mixes of `+ - ^ & | ~`. E.g. `a + b = (a ^ b) + 2*(a & b)`.
  *Why:* algebraic simplifiers and humans struggle to re-derive the original.
  **In CodeScrambler: DONE** — `mutation.mba`, with a **numeric self-check** that
  rejects any non-equivalent expansion.
- **String encryption / "static data to procedure".** Store strings encrypted;
  decrypt at use with a small inline routine, so plaintext never sits in the file.
  *Why:* string scans (a top recon technique) come up empty.
  **In CodeScrambler: PARTIAL.** Whole non-exec *sections* are encrypted at rest
  (`protect`), which hides bulk string data. **Per-string inline** encryption is
  **SKIPPED** — it needs reliable detection of which bytes are strings and where
  they're referenced, which is hard in stripped binaries (see §10).
- **Variable / array splitting, merging, folding, reordering.** Restructure data
  aggregates so their shape misleads analysis.
  **In CodeScrambler: SKIPPED.** These are *source/type-level* transforms; on a
  compiled binary the variable structure is already lowered to memory offsets, so
  there's little to restructure safely without type information.

### 2.3 Control obfuscation
Hiding *how control flows*.

- **Opaque predicates.** A condition whose value the author knows but an analyzer
  cannot easily prove (e.g. always-true), used to add fake branches and guard
  dead code.
  *Why:* inflates the control-flow graph with paths that never execute.
  *Counter:* prove the predicate (alias analysis, SMT solvers).
  **In CodeScrambler: DONE** — `mutation.opaque` (always-true predicate guarding
  dead junk, wrapped in `pushf/popf` so flags survive).
- **Dead / junk code insertion.** Add instructions with no effect on the result.
  *Why:* dilutes signal with noise; changes byte patterns.
  **In CodeScrambler: DONE** — `mutation.junk` (register/flag-preserving) and
  `mutation.stacknoise` (balanced `lea rsp,[rsp±N]`).
- **Instruction substitution.** Replace an instruction with an equivalent one or
  sequence (`mov`→`lea`, `add`→`sub` of a negative, …).
  *Why:* breaks instruction-level signatures; multiplies variants.
  **In CodeScrambler: DONE** — `mutation.substitute`.
- **Instruction reordering.** Swap independent adjacent instructions.
  *Why:* perturbs layout without changing semantics.
  *Safety:* only swap when there's no data/flag/memory dependency.
  **In CodeScrambler: DONE** — `mutation.reorder` (skips dependent or synthetic
  instructions).
- **Jump / call indirection.** Replace fall-through with explicit jumps; turn
  `call t` into `push return; jmp t`.
  *Why:* obscures the literal call graph.
  **In CodeScrambler: DONE** — `mutation.jumps`, `mutation.callswitch` (x86;
  x64 documented as an open item because the 64-bit return address can't be
  pushed as an immediate without a proven-dead scratch register).
- **Block splitting / scattering.** Cut the code into basic blocks and **shuffle
  their physical order**, relinking fall-through edges with explicit jumps, so the
  linear layout no longer matches execution order.
  *Why:* a linear reader can't follow the program top-to-bottom; cheap and safe.
  **In CodeScrambler: DONE** — `mutation.scatter` (`BlockScatterPass`), built on
  `core/cfg.py`. Correct by construction: every inter-block edge becomes a
  symbolic label, fall-through blocks get an explicit `jmp`, and a trailing
  fall-through block is pinned.
- **Control-flow flattening.** Replace structured control flow with a single
  dispatcher loop + `switch` on a "state" variable, so the original block order
  is destroyed.
  *Why:* one of the strongest control obfuscations; the CFG becomes a star, not a
  story.
  *Counter:* recover the state machine via symbolic execution.
  **In CodeScrambler: SKIPPED (designed) — building blocks shipped.** The CFG
  model (`core/cfg.py`) and block scattering are in; *full* flattening additionally
  needs a **persistent state variable** that survives every trip through the
  dispatcher. Doing that correctly means a writable in-image slot (RWX code
  section + RIP-relative addressing on x64, or a reloc'd absolute on x86) — a
  runtime-critical change we won't commit unverified. Scattering is the safe
  subset we ship today.
- **Branch functions / indirect dispatch.** Replace direct jumps with a transfer
  that computes the destination at runtime, removing the explicit edge.
  **In CodeScrambler: DONE** — `mutation.branchfunc` (`BranchFunctionPass`):
  x86 `push {target}; ret`; x64 `push rax; mov rax,{target}; xchg rax,[rsp]; ret`
  (register- and flag-neutral, so correct without a dead register). The absolute
  target is filled in by the assembler's label mechanism.
- **Loop transformations** (unrolling, splitting, fission/fusion).
  **In CodeScrambler: SKIPPED.** Needs loop recognition (a CFG analysis on top of
  `core/cfg.py`); low priority relative to flattening.
- **Aggregation: inlining / outlining / cloning / interleaving.** Merge callees
  into callers (inline), split code into fake functions (outline), duplicate a
  function into specialized copies (clone), or weave two functions together
  (interleave).
  *Why:* destroys the function-boundary abstraction analysts rely on.
  **In CodeScrambler: SKIPPED.** Requires a call graph and precise boundary
  detection; risky on stripped binaries.

### 2.4 Virtualization (table interpretation)
**What it is.** Translate selected native code into bytecode for a **custom
virtual machine** that you ship with the program; the original instructions are
gone, replaced by a call into your interpreter.
**How it works.** Define a private instruction set, *lift* native runs into it,
*encrypt* the bytecode, and generate an interpreter (dispatcher + handlers). To
read the code, an attacker must reverse the interpreter, then the ISA, then the
encryption.
**Why it helps.** The strongest common obfuscation; raises the cost enormously,
especially when the VM is **randomized per build**.
**Attacker's counter.** Reverse one VM and script the rest; devirtualization
research targets fixed VMs — which is exactly why ours is polymorphic.
**In CodeScrambler: DONE (off-target) / PARTIAL (commit).** `vm` implements the
ISA, per-build randomizer, encrypted bytecode (verified round-trip), a lifter
with an equivalence self-check, and an interpreter generator that assembles.
**Replacing** the native code with a call into the interpreter inside the rebuilt
PE ("commit") is **GATED** until validated on a real machine.

### 2.5 Anti-disassembly
**What it is.** Exploit how disassemblers work to make them produce *wrong*
instructions.
**How it works.** *Linear sweep* decodes bytes sequentially; feed it bytes that,
mid-instruction, look like the start of a long instruction so it mis-aligns.
*Overlapping instructions* make one byte stream decode two ways depending on
entry point.
**Why it helps.** Wrong disassembly → wrong analysis, broken decompilation.
**Attacker's counter.** Recursive-descent disassembly that follows control flow;
manual fixups.
**In CodeScrambler: DONE (junk-byte variant).** `mutation.antidisasm` emits
`jmp over; .byte <decoy>; over:` — the decoy is *strictly between* a guaranteed
jump and its target, so it is **provably unreachable** (correct by construction)
yet desyncs a linear sweep. Full *overlapping* instructions are **SKIPPED** (hard
to keep provably correct).

---

## 3. Encryption & packing

### 3.1 Section / data encryption at rest
**What it is.** Store sections encrypted on disk; decrypt in memory before use.
**How it works.** A runtime stub decrypts each protected section, then control
proceeds normally.
**Why it helps.** Hides data (and code) from static inspection entirely.
**In CodeScrambler: DONE (non-exec).** `protect` encrypts safe non-executable
sections (never the ones the loader reads before our stub runs), installs a
position-independent decryptor, and redirects the entry point.

### 3.2 Executable packing
**What it is.** Encrypt/compress the *code* too, unpacking at runtime.
**How it works.** Needs the stub to make pages writable, unpack, re-protect as
executable, and honor relocations.
**In CodeScrambler: SKIPPED (designed).** Encrypting `.text` requires a
reloc-aware, `VirtualProtect`-using stub — a clear extension of the existing
stub, deferred because it cannot be runtime-verified here.

### 3.3 White-box cryptography
**What it is.** Implement a cipher so the *key is never present* even in memory —
it's baked into lookup-table networks.
**Why it helps.** Protects embedded keys from an attacker who fully controls the
machine (the white-box threat model).
**In CodeScrambler: SKIPPED.** A large, self-contained subproject; orthogonal to
PE rewriting.

---

## 4. Preventive / anti-analysis

### 4.1 Anti-debugging
**What it is.** Detect (or hinder) a debugger and react.
**How it works.** Cheap checks: the OS sets a `BeingDebugged` flag in the Process
Environment Block (PEB); debuggers leave other artifacts (`NtGlobalFlag`, heap
flags), trip timing checks (a single step is slow — measure with RDTSC), or use
hardware breakpoint registers (DR0–DR7).
**Why it helps.** Dynamic analysis is the fastest path to understanding; deterring
it is high-value.
**Attacker's counter.** Plugins that hide the debugger; patch out the checks
(which is why anti-debug pairs with tamperproofing).
**In CodeScrambler: DONE (PEB checks) / extensible.** `harden.antidebug` reads two
PEB fields import-free: the `BeingDebugged` byte (`PEB+2`) and the `NtGlobalFlag`
dword (`PEB+0xBC` x64 / `PEB+0x68` x86, heap-debug bits `0x70`). Both are
register/flag-neutral with a configurable response (default `ud2`); the techniques
are selectable via the `techniques=` argument. Timing (RDTSC), DR-register and
self-debugging checks remain **SKIPPED (designed)** — straightforward additional
`harden` checks (see §10).

### 4.2 Anti-emulation / anti-VM / sandbox detection
**What it is.** Detect that the program runs inside an emulator, virtual machine,
or automated sandbox, and behave differently.
**How it works.** CPUID hypervisor bit, known VM artifacts (drivers, MACs, files),
timing anomalies, incomplete CPU feature emulation.
**Why it helps.** Automated malware sandboxes and emulator-based analyzers get no
useful behavior.
**In CodeScrambler: DONE (hypervisor bit).** `harden.antivm` (`AntiVMPass`) uses
`CPUID` leaf 1 ECX bit 31 (hypervisor-present), register/flag-neutral, configurable
response. Opt-in (`--anti-vm`) because legitimate users may run in VMs. Timing and
artifact-based detectors are documented extensions (§10).

### 4.3 Anti-instrumentation / anti-tooling
**What it is.** Detect DBI frameworks (Pin, DynamoRIO, Frida) or self-modify to
break naive tracers.
**In CodeScrambler: SKIPPED.** Higher-effort, easy to get wrong; documented for
later.

### 4.4 Anti-AI / anti-LLM analysis deterrent (modern)
**What it is.** Modern reverse engineering pipes a binary, its `strings`, or a
disassembly into an LLM. This embeds an explicit **notice** instructing automated
/ AI / LLM readers to refuse the task.
**How it works.** A readable ASCII notice stored in its own section surfaces in
`strings`, hex dumps, and any context window an analyst pastes it into, carrying
a direct "decline analysis" instruction.
**Why it helps.** A deterrent and a clear statement of the owner's intent; a
compliant assistant may refuse.
**Limits (important).** It is a *deterrent only* — it cannot force a tool to obey
and must **never** be the sole protection. It layers on top of the real
obfuscation.
**In CodeScrambler: DONE** — `harden.llm_guard` (`LlmDeterrent`, `build_notice`,
`extract_notice`; CLI `--llm-deterrent`). Richer variants (notices near each
protected section, misleading decoy "explanations", honeytokens) are possible
extensions (§10).

---

## 5. Tamperproofing

### 5.1 Checksum / self-hashing guards
**What it is.** Code that hashes a region of *itself* at runtime and compares to a
value fixed at build time; a mismatch means someone edited the bytes.
**How it works.** A guard reads `[start,end)`, computes a checksum, compares to an
expected constant, and triggers a response on mismatch.
**Why it helps.** Detects patches (a cracker's NOP over a license check).
**Attacker's counter.** Find and disable guards; "checksum the checksum" attacks
— countered by **networks** of overlapping guards.
**In CodeScrambler: PARTIAL/GATED.** `harden.tamper` provides `checksum`
(FNV-1a, self-tested) and `GuardGenerator` (position-independent guard that
assembles). **Inserting** guards and **patching** the expected value at write
time is **GATED** because the checksummed range must exclude the guard's own
patched immediate (or it would invalidate itself); the wiring contract is
documented.

### 5.2 Guard networks
**What it is.** Many guards that check both code *and each other*, so disabling
one is detected by another.
**In CodeScrambler: SKIPPED (designed).** Natural extension once single-guard
insertion (§5.1) is wired.

### 5.3 Oblivious hashing
**What it is.** Weave a hash of *computed runtime values* into the program's
normal results, so tampering with logic corrupts output rather than tripping an
obvious check.
**Why it helps.** No discrete "if (hash != X)" for an attacker to find.
**In CodeScrambler: SKIPPED.** Requires dataflow integration; advanced.

### 5.4 Response mechanisms
**What it is.** What to do on detection: crash, corrupt silently, degrade,
phone home, or delay (so the cause is far from the check).
**In CodeScrambler: DONE (basic).** Anti-debug and the guard generator take a
configurable response (`ud2`/`int3`/`hlt`). Stealthy/delayed responses are a
documented refinement.

### 5.5 Remote tamperproofing / attestation
**What it is.** A trusted server checks the client's integrity over the network.
**In CodeScrambler: OUT OF SCOPE.** Needs server infrastructure and a protocol.

---

## 6. Watermarking & fingerprinting

### 6.1 Static watermarks
**What it is.** A hidden identifier embedded in the binary's static content
(prove ownership / trace a leak).
**How it works.** Encode an ID into data or code in a recoverable way.
**Attacker's counter.** Find and strip it; distortive attacks — countered by
robust/spread encoding.
**In CodeScrambler: DONE (basic).** `harden.watermark` embeds an ID as a data
section (`"CSWM" | key | len | xor(payload)`); `extract_watermark(path)` recovers
it. (Robust, error-correcting encoding is a refinement — §10.)

### 6.2 Dynamic / CT (Collberg-Thomborson) watermarks
**What it is.** Encode the mark in a data structure (e.g. a graph) built in the
heap **at runtime** only when fed a special secret input.
**Why it helps.** Far harder to find/strip than a static mark, since it isn't
present until triggered.
**In CodeScrambler: SKIPPED (designed).** Requires runtime data-structure
construction + a trace-based recovery tool.

### 6.3 Fingerprinting
**What it is.** Like watermarking, but a *different* mark per customer, to trace
*which* copy leaked.
**In CodeScrambler: PARTIAL.** Achievable today by giving each customer a unique
`--watermark` string (and/or a unique `--seed` for unique code); a managed
fingerprint registry is an app-level add.

### 6.4 Birthmarking
**What it is.** *Identifying* software by its intrinsic characteristics (no mark
added) — used to detect theft/clones.
**In CodeScrambler: OUT OF SCOPE.** It's an analysis/identification technique, not
a protection transform.

---

## 7. Hardware-assisted protection

**What it is.** Dongles, TPM-bound keys, CPU enclaves (SGX), node-locking to
hardware IDs, secure boot.
**Why it helps.** Anchors trust outside the attacker-controlled software.
**In CodeScrambler: OUT OF SCOPE.** Requires external hardware/OS services beyond
a static PE rewriter.

---

## 8. At-a-glance scorecard

| Technique | Status | Where / why |
|-----------|--------|-------------|
| Polymorphism | DONE | `protect`, `vm` (per-build keys/opcode maps) |
| Metamorphism (build-time) | DONE | `mutation` (rewrites real instructions) |
| Constant encoding | DONE | `mutation.constants` |
| MBA | DONE | `mutation.mba` (+ self-check) |
| Opaque predicates | DONE | `mutation.opaque` |
| Junk / stack noise | DONE | `mutation.junk`, `mutation.stacknoise` |
| Instruction substitution | DONE | `mutation.substitute` |
| Instruction reordering | DONE | `mutation.reorder` |
| Jump / call indirection | DONE | `mutation.jumps`, `mutation.callswitch` (x86) |
| Block splitting / scattering | DONE | `mutation.scatter` (+ `core/cfg.py`) |
| Branch functions / indirect dispatch | DONE | `mutation.branchfunc` (x86 + x64) |
| Anti-disassembly (junk bytes) | DONE | `mutation.antidisasm` |
| Virtualization | DONE / commit GATED | `vm.*` |
| Section encryption (non-exec) | DONE | `protect.*` |
| Anti-debugging (PEB + NtGlobalFlag) | DONE | `harden.antidebug` |
| Anti-VM / anti-emulation (CPUID) | DONE | `harden.antivm` |
| Static watermark | DONE | `harden.watermark` |
| Anti-AI/LLM deterrent | DONE | `harden.llm_guard` |
| Checksum-guard tamperproofing | PARTIAL/GATED | `harden.tamper` |
| Control-flow flattening | SKIPPED | CFG model shipped; needs persistent state slot |
| Register renaming | SKIPPED | needs full liveness dataflow |
| Inline/outline/clone/interleave | SKIPPED | needs call graph + boundaries |
| Per-string inline encryption | SKIPPED | needs string-ref detection |
| Executable packing | SKIPPED | reloc-aware `VirtualProtect` stub |
| Anti-instrumentation | SKIPPED | high effort/fragile |
| Guard networks | SKIPPED | after single-guard wiring |
| Oblivious hashing | SKIPPED | needs dataflow |
| Dynamic / CT watermark | SKIPPED | runtime structure + tracer |
| Runtime metamorphism | SKIPPED | self-rewriting stub |
| White-box crypto | SKIPPED | table-network subproject |
| Layout/lexical, variable splitting | OUT OF SCOPE | source/type-level |
| Birthmarking | OUT OF SCOPE | identification, not protection |
| Hardware anti-piracy, remote attestation | OUT OF SCOPE | external hardware/server |

---

## 9. Why we skipped what we skipped (the short version)

Three honest reasons, in priority order:

1. **Correctness over coverage.** Anything we can't prove safe in memory (no PE
   files are produced here, by your request) is either gated or deferred rather
   than shipped half-working. Full flattening (persistent state slot), register
   renaming, executable packing and runtime metamorphism all change control/data
   flow or memory permissions in ways that *must* be validated on-target. (The
   safe subsets — block scattering, branch functions — are shipped.)
2. **Missing prerequisites.** Several techniques need a structure we haven't built
   yet: a writable in-image state slot (full flattening — the CFG model itself is
   now shipped in `core/cfg.py`), full backward register liveness (renaming), a
   call graph (inline/outline), or reliable string-reference detection (per-string
   encryption).
3. **Scope.** Birthmarking, hardware anti-piracy, remote attestation and white-box
   crypto are different problem domains from a static PE rewriter.

None of the skips are dead ends — §10 lists how to add each.

---

## 10. What to look at next (concrete starting points)

- **Full control-flow flattening.** `core/cfg.py` is shipped; the remaining piece
  is a persistent state slot (RWX code section + RIP-relative on x64, or a reloc'd
  absolute on x86) plus a dispatcher pass — runtime-critical, hence deferred.
- **Backward liveness in `core/analysis.py`.** Promote the conservative helpers to
  a real dataflow pass → safe register renaming and better scratch selection.
- **Executable packing in `protect`.** Extend the stub to `VirtualProtect` pages
  and apply relocations after unpacking.
- **More `harden` checks.** Advanced anti-debug (RDTSC timing, DR registers,
  self-debugging), anti-VM artifact/timing detectors, entry-stub randomization
  (writer post-hook), richer anti-AI decoys. (CPUID anti-VM and NtGlobalFlag
  anti-debug are now shipped.)
- **Wire the tamper guard.** Complete `harden.tamper`: pick a stable range,
  compute `expected`, append the guard, then build guard *networks*.
- **Dynamic watermarking.** A runtime heap-graph encoder + a trace-based recovery
  tool, layered over the static mark.
- **Robust static marks.** Error-correcting / spread-spectrum encoding so the
  watermark survives partial edits.

---

## 11. References & further reading

- C. Collberg, J. Nagra — *Surreptitious Software: Obfuscation, Watermarking, and
  Tamperproofing for Software Protection* (2009).
- C. Collberg, C. Thomborson, D. Low — *A Taxonomy of Obfuscating Transformations*
  (1997).
- C. Wang et al. — control-flow flattening.
- D. Aucsmith — tamper-resistant software (integrity verification).
- H. Chang, M. Atallah — software guards / guard networks.
- Y. Zhou et al. — Mixed Boolean-Arithmetic obfuscation.
- S. Chow et al. — white-box cryptography.
- Internal: [ARCHITECTURE.md](ARCHITECTURE.md), [FEATURES.md](FEATURES.md),
  [ARCHITECTURE_SIMPLE.md](ARCHITECTURE_SIMPLE.md).
