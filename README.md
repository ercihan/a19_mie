# Memory Tagging Under Pressure: Hunting an MTE Ordering Race in iOS 26.x

A connected five-paper investigation into a **candidate time-of-check to time-of-use (TOCTOU) ordering race** in the iOS kernel's Memory Tagging Extension (MTE) tag-generation path on A19-class Apple silicon (iPhone 17 series). The series moves from static reverse engineering of the tagging helper to physical-device dynamic validation under allocator pressure and timing perturbation.

**Author:** Kaya Ercihan

**Target stack:** iOS 26.0.1 / 26.5 / 26.5.1 (Darwin 24.x), A19 (ARMv9.2-A), iPhone 17 / 17e

**Tooling:** IDA Pro 9.1 + IDA Python (static), `MTETrigger.app` C/SwiftUI harness (dynamic)

**Headline status:** The tag-generation helper (`irg_mte_function`, reverse-mapped to `vm_memtag_generate_and_store_tag()`) carries no explicit `DMB`/`DSB`/`ISB` barrier in its body. Across the analysed direct-caller paths, only one caller context carries an explicit barrier; no complete barrier, lock, or acquire/release publication protocol was identified on the remaining traced segments. This supports a conditional CWE-362 ordering hypothesis, subject to higher-level synchronization outside the analysed paths. Reachability and concurrent allocator pressure are demonstrated on-device; **no exploitable race or MTE tag fault was confirmed.**

## The investigation

The work asks a narrow ordering question: not whether the MTE instructions (`IRG`, `STG`, `ST2G`, `STGM`) are individually incorrect, but whether a tag store is correctly ordered with respect to the later publication, recycling, or consumption of the same object across execution contexts. Static analysis raises the hypothesis; the dynamic papers try, and so far fail, to turn it into an observable fault on real hardware.

## Papers (reading order)

### 00: Static analysis, iOS 26.0.1 MTE tag generation
[`00_static_analysis_ios26_0_1_mte_tag_generation.pdf`](./00_static_analysis_ios26_0_1_mte_tag_generation.pdf), 2026-03-01 *Investigating a Potential TOCTOU in the iOS 26.0.1 MTE Tagging Path.* Static reverse engineering (IDA Pro 9.1 + IDA Python) of `irg_mte_function` and its direct caller contexts in the iOS 26.0.1 kernel. Of the traced helper-to-publication paths, only one caller context carries an explicit barrier; the rest contain no explicit architectural barrier, with acquire- and release-qualified atomics present but no complete end-to-end publication protocol. Forms the conditional CWE-362 ordering hypothesis. No dynamic validation (no MTE-capable hardware).

### 01: Caller-to-trigger correlation, iOS 26.5
[`01_ios26_5_xnu_mte_trigger_path_correlation.pdf`](./01_ios26_5_xnu_mte_trigger_path_correlation.pdf), 2026-06-11
*iOS 26.5 MTE Tagging Paths: Caller-Trigger Correlation and TOCTOU Preconditions.* Carries the static analysis to iOS 26.5, maps the helper to `vm_memtag_generate_and_store_tag()`, and correlates the binary caller graph to userland-controllable pressure surfaces: Mach IPC / zone allocation and BSD socket / Skywalk slab allocation. Produces the caller-to-trigger correlation matrix used by the dynamic harness.

### 02: Dynamic testing, trigger reachability and timing limits
[`02_dynamic_testing_trigger_reachability_and_timing_limits.pdf`](./02_dynamic_testing_trigger_reachability_and_timing_limits.pdf), 2026-06-16 *Physical-Device Evaluation of a Potential TOCTOU in the iOS MTE Tagging Path on iPhone 17e / iOS 26.5.1.* First on-device run using the `MTETrigger.app` harness. Drives zone-only parallel pressure with Skywalk as a sequential reachability path. Demonstrates the mapped syscall surface and concurrent workload (12,443,103 overlap-counter increments) but observes no MTE tag-fault signature.

### 03: Dynamic testing, allocator-pressure validation
[`03_dynamic_testing_allocator_pressure_validation.pdf`](./03_dynamic_testing_allocator_pressure_validation.pdf), 2026-06-24 *Dynamic Pressure Validation for Potential iOS Kernel MTE Allocator-State Races.* Adds structured execution classes: FAST, PIPELINE, FLOOD, PREFILL_FLOOD, and PENDING_FLOOD, plus a `BGProcessingTask` background wrapper. Produces strong intermediate evidence (trigger execution, allocator pressure, phase overlap, clean background admission) but remains negative for a confirmed same-object stale-tag race or tag fault.

### 04: Dynamic testing, timing-perturbation validation
[`04_dynamic_testing_timing_perturbation_validation.pdf`](./04_dynamic_testing_timing_perturbation_validation.pdf), 2026-08-03 *Dynamic Timing-Perturbation Validation for Potential iOS Kernel MTE Allocator-State Races.* Adds a timing-perturbation layer: user-configurable NOP timing jitter, a requested `MAP_JIT` sled backend, mixed ARM64 timing instructions, a signed static fallback, and five zone-pressure modes compared across a fifteen-execution matrix. On the tested iPhone 17e both `MAP_JIT` mappings failed, so the campaign ran on precompiled pure-NOP sleds. All runs are negative for an externally generated MTE tag-fault signature; broadens black-box configuration coverage without confirming the race.

## Scope and framing

Defensive security research. The series characterizes a *candidate* ordering weakness through static analysis and bounded on-device validation; it does not demonstrate a working exploit, a user-space exploitation path, or a confirmed tag fault. Results are reported with an explicit evidence boundary separating demonstrated reachability/pressure from unproven exploitability.
