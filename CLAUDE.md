
# CLAUDE.md — Technical Interview Guide: Multi-Stage Attack Orchestrator

## Instructions for Claude / Agent

* **Context:** This document serves as the primary study guide for a technical interview on the Multi-Stage Attack Orchestrator project.
* **Goal:** Review the codebase and architecture details below to quickly refresh on core system design, key decisions, edge cases, and potential interview questions.
* **Execution:** Use the synthesized sections below to prepare verbal walkthroughs, trade-off defenses, and technical deep-dives.

---

## Assignment Overview & Core Value

* **Project Purpose:**
  * A framework that selects a compatible unlocking attack from a registry for a given mobile device, executes it stage by stage, and extracts data upon success.
* **Core & Important Features Built:**
  * **Decision Engine (`orchestrator/`):** Pure Python decision-making system that filters/ranks attacks, handles mid-chain stage failures, connection drops, and device crashes, and extracts target files.
  * **C Device Simulator (`simulator/`):** A TCP-based simulator written in C that mimics a real mobile device, simulating stage outcomes, silent connection drops, and device crashes.
  * **Test Suite (`tests/`):** 72 tests — unit tests using an in-memory `FakeProtocol` (a real in-memory `Protocol` implementation, not a mock library) alongside end-to-end integration tests using `TCPProtocol` against the compiled C binary.

---

## Architecture & System Structure

* **Core Components:**
  * `Orchestrator`: Coordinates the full execution flow, managing connection lifecycle, attack fallbacks, and reconnects.
  * `AttackSelector`: Filters candidate attacks against device state and ranks them into an execution queue. Pure logic, no I/O.
  * `Attack` & `Stage`: Encapsulate multi-stage attack pipelines and individual execution steps.
  * `Protocol` (`TCPProtocol` / `FakeProtocol`): Abstraction layer separating high-level orchestrator logic from low-level wire/network communication.
  * `Session` & `AttackContext`: `Session` handles post-unlock operations (file reading, file listing, extraction); `AttackContext` threads shared execution context (protocol, device snapshot, scratch dict) through every stage.
* **End-to-End Execution Flow:**
  1. `Orchestrator` connects and queries device state via `Protocol` (`HELLO` command).
  2. `AttackSelector` filters compatible attacks and ranks them into a queue based on calculated probability (empty queue → `NoViableAttackError`).
  3. `Orchestrator` takes the top candidate and executes its stages sequentially (`STAGE <id>`); on failure it advances to the next candidate in the queue.
  4. Once all of an attack's stages succeed, `Attack.run()` issues `UNLOCK` and the `Orchestrator` returns an active `Session` with the connection still open.
  5. The client uses `Session.extract_all()` or `Session.read_file()` to extract data via `LIST` and `READ` commands.
* **Design Patterns & Conventions:**
  * **Strategy:** `Attack` and `Stage` are interchangeable implementations behind a shared `run(context)` shape; callers never branch on the concrete type.
  * **Composite:** An `Attack` exposes a single `run()` method to the `Orchestrator`, wrapping an ordered list of `Stage` objects.
  * **Bridge:** `Protocol` separates the attack/stage execution logic from the underlying communication mechanism (TCP socket vs. in-memory fake).

---

## Domain Concepts: Device State

`DeviceState` is the immutable snapshot every attack checks itself against. Six fields, each grounded in how real mobile forensic tooling gates low-level extraction:

* **`model`** — hardware/chipset generation. Bootrom exploits target specific silicon, not "an iPhone."
* **`ios_version`** — compared numerically by point release via `IOSVersion` (an exploit viable on 15.7 may be patched by 16.0).
* **`battery`** — insufficient charge is a real reason a low-level attempt can't start. A bootrom exploit needs far less than one that must stay powered through a sideload + reboot.
* **`locked`** — whether the device currently needs unlocking. **Not a compatibility gate** — an attack's whole job is to get from locked to unlocked.
* **`after_first_unlock` (AFU vs. BFU)** — **AFU** = the passcode has been entered at least once since the device last booted, so keychain / pairing / decryption-key state exists in memory. **BFU** = booted but passcode never entered; most data is still encrypted at rest. Independent of `locked`: a device can be AFU but currently re-locked at the lock screen. `agent_style` requires AFU because sideloading needs pairing/keychain state that only exists post-unlock.
* **`jailbroken`** — whether the device already has a working jailbreak from a prior run. `jailbreak_ssh_style` requires this and rides the existing jailbreak over SSH instead of exploiting.

Defaults: AFU and stock (not jailbroken) — the common cases. `HELLO` replies missing `afu`/`jailbroken` fall back to these.

---

## The Attack Registry

Four example attacks, modeled loosely on real-world families. Each is an `Attack` subclass that just sets class-attribute compatibility bounds and a stage list.

| Attack | Models | iOS range | Min battery | Requires | Stages (probability) | Est. success |
| --- | --- | --- | --- | --- | --- | --- |
| `checkm8_style` (bootrom exploit) | `iPhone8,1/8,2/10,1/10,4/12,1` | ≤ 15.7 | 10 | — | enter_dfu (.95), exploit_bootrom (.90), mount_ramdisk (.95) | **0.812** |
| `checkrain_style` (checkra1n-style jailbreak) | `iPhone10,1/10,4` | ≤ 14.8 | 15 | — | + boot_patched_kernel (.90), install_cydia_substrate (.85) | **0.654** |
| `agent_style` (sideloaded-agent priv-esc) | any | ≥ 15.0 | 40 | AFU | sideload_agent (.75), establish_trust (.90), elevate_privileges (.80) | **0.540** |
| `jailbreak_ssh_style` (existing-jailbreak SSH) | any | any | 5 | jailbroken | connect_via_ssh (.98), mount_root_filesystem (.97) | **0.951** |

**Selection scenarios the tests exercise:**

* **`checkm8` vs `checkrain` on shared hardware:** On an `iPhone10,1` at iOS ≤ 14.8 with ≥ 15% battery, both are compatible. `checkm8` (0.812) ranks above `checkrain` (0.654), so `checkm8` runs first and `checkrain` is the fallback if it fails.
* **`jailbreak_ssh_style` joins once jailbroken:** If `HELLO` reports `jailbroken=1`, this attack becomes compatible and ranks first (0.951) — it skips the hard exploit work entirely.
* **`checkm8` vs `agent_style` overlap:** iOS 15.0–15.7 on bootrom-vulnerable hardware with ≥ 40% battery and AFU makes both compatible; `checkm8` (0.812) wins the ranking.
* **Empty queue:** nothing compatible → `NoViableAttackError` before any stage runs.
* **Tie-break:** an exact probability tie is broken by fewer stages (isolated in `test_selector.py` with two synthetic attacks built for an exactly-representable tie, 0.5 × 0.5).

---

## Wire Protocol (Part 2)

**Framing:** every message, both directions, is one frame: `[4 bytes: payload length, big-endian uint32][N payload bytes]`. Big-endian = network byte order, removes C/Python native-order ambiguity. The receiver always knows the byte count, so framing never scans for a delimiter — which matters because `READ`'s reply embeds raw file bytes that can contain any byte, including `\n`. Zero-length, oversized (`> 64 KiB`), or mid-frame EOF are protocol errors.

**Payload content** is plain text for every command and most responses. `READ`'s reply is the one structured payload: a text header, one `\n`, then raw file bytes filling the rest of the frame. The receiver splits on the *first* `\n` only and takes the rest by length.

| Command (client → server) | Purpose |
| --- | --- |
| `HELLO` | Ask for device info |
| `STAGE <id>` | Execute one attack stage by numeric id |
| `UNLOCK` | Mark device unlocked (after all stages in a chain succeed) |
| `READ <path>` | Read one file (only once unlocked) |
| `LIST` | Enumerate extractable paths (only once unlocked) |
| `QUIT` | Close the session cleanly |

| Response (server → client) | Meaning |
| --- | --- |
| `OK HELLO model=<m> ios=<v> battery=<0-100> locked=<0\|1> afu=<0\|1> jailbroken=<0\|1>` | device info |
| `OK STAGE <id> SUCCESS` / `OK STAGE <id> FAIL` | stage outcome |
| `ERR CRASH <id>` | device reports the stage crashed it, then the connection closes |
| `OK UNLOCK locked=0` | unlock acknowledged |
| `OK READ <path> <len>\n<raw bytes>` | file content, one frame |
| `OK LIST <n>\n<path 1>\n…\n<path n>` | file listing, one frame |
| `OK BYE` | ack for `QUIT` |
| `ERR LOCKED` / `ERR NOTFOUND <path>` / `ERR UNKNOWN <command>` | error replies |

**Three failure modes on the wire** (these are the whole reason the simulator exists — a device that could only succeed or `FAIL` wouldn't exercise the orchestrator's failure policy):

* **`FAIL`** — device responded, stage didn't succeed → stage-logic failure.
* **Silent drop** — socket just closes at a frame boundary, no `ERR`. The client's *read fails*. Mirrors a cable pull / bootloader hang → transient, retry.
* **`ERR CRASH <id>`** — device replies, *then* closes. The client's *read succeeds* — that success is the signal distinguishing a crash from a drop → verdict on the exploit, no retry.

**Simulator config is CLI-only** (`--model`, `--ios`, `--battery`, `--fail-stage`, `--drop-stage`, `--crash-stage`, `--bfu`, `--jailbroken`) — "what should this fake device do" is a test-setup concern a real device would never expose over the wire.

---

## Technical Trade-offs & Decisions

1. **Two-Phase Attack Selection (Filter-Then-Rank) vs. Decision Tree:**

   * *Chosen Approach:* Filter candidate attacks using `Attack.is_compatible()`, then rank remaining candidates by total probability (product of stage probabilities). Ties broken by shorter stage count.
   * *Alternative Considered:* Decision tree based on device attributes.
   * *Justification:* Attack compatibility checks are flat conjunctions of independent checks (model, iOS version, battery, AFU/BFU, jailbreak status). A decision tree adds unnecessary structural complexity without branching benefits. Returning a ranked *queue* rather than a single pick is what makes the fallback behavior in decision 3 possible.

2. **Sequential Loop for Stage Execution vs. Chain of Responsibility (CoR):**

   * *Chosen Approach:* Simple `for stage in self.stages:` execution loop inside `Attack.run()`.
   * *Alternative Considered:* Chain of Responsibility pattern where each stage invokes the next.
   * *Justification:* CoR is useful when stage sequences are dynamically assembled or decoupled at runtime. Since an attack's stage sequence is fixed at construction, a plain loop provides the same behavior without `set_next()` overhead.

3. **Explicit Failure Classification (Logic Failure vs. Drop vs. Crash):**

   * *Chosen Approach:* Three distinct failure modes:
     * *Stage Logic Failure:* Device responded, the stage just returned `FAIL`. Abort attack, fall through to next candidate in queue without retrying.
     * *Connection Drop:* Silent socket close, no response. Transient error; reconnect and retry the same attack from the start (up to `max_connection_retries`, default 2).
     * *Device Crash (`DeviceCrashed`):* Device sent `ERR CRASH <id>` before the connection closed. A verdict on the exploit, not a transient fault, so it gets the logic-failure treatment (abort attack, no retry). Because the crash leaves the socket dead, `Orchestrator.run()` reconnects proactively before the next candidate runs.
   * *Alternative Considered:* Treating all errors uniformly as connection drops or fatal exceptions; making `DeviceCrashed` a subclass of `ConnectionDropped`.
   * *Justification:* Mid-chain drops can leave a device in a state the framework can't reason about, so retrying from a clean connection is safer than resuming. Crashes indicate the exploit broke the device, so retrying the same attack is useless and would waste the connection-retry budget.

---

## Edge Cases, Reliability & Error Handling

* **Handled Edge Cases:**
  * **Phantom Connection Drop on Fallback:** Proactive socket reconnection before passing control to the next candidate attack, preventing the next attack from inheriting a dead socket from the previous failed attempt and misreporting it as its own connection drop.
  * **Session on a Dead Socket:** `Orchestrator.run()` deliberately does *not* wrap the protocol in a `with` block — the success path must return a `Session` with the connection still open. (Real bug caught by integration tests.)
  * **Partial Extraction Failure:** `Session.extract_all()` operates on a best-effort, per-file basis. Unreadable/missing files (`ERR NOTFOUND`, `ERR LOCKED`) are captured in `ExtractionResult.errors` and extraction continues. A connection drop or device crash mid-extraction is different — the channel is gone, so the loop stops immediately and is recorded once in `ExtractionResult.aborted`.
  * **Length-Prefixed TCP Framing:** 4-byte big-endian length prefix frames remove any dependence on scanning for a delimiter, safely handling embedded newlines (`\n`) in raw file payloads. Zero-length or oversized (`> 64 KiB`) frames are protocol errors.
  * **`READ` Length Mismatch:** The declared content length in the `READ` header is validated against the actual bytes received; a mismatch raises `ProtocolError`.
  * **Numerical iOS Version Comparison:** Custom `IOSVersion` class compares version tuples numerically so "9.0" sorts before "15.0" (preventing naive string comparison bugs); missing minor parts are zero-padded ("14.4" == "14.4.0").
  * **Backward-Compatible `HELLO`:** Missing `afu` / `jailbroken` fields fall back to `DeviceState` defaults (AFU, stock); missing `model` / `ios` / `battery` / `locked` raise `ProtocolError`.
* **Error Handling Strategy:**
  * Single rooted exception hierarchy (`OrchestratorError`), one class per *reason*, because the orchestrator's retry/abort/fallback logic branches on *why* something failed.
  * `DeviceCrashed` and `ConnectionDropped` are **sibling** exceptions, not parent/child. This prevents a broad `except ConnectionDropped` handler from mistakenly applying connection-retry logic to a device crash.
  * `TCPProtocol` translates raw `OSError` from the socket into `ConnectionDropped` at the boundary, and parse failures into `ProtocolError`.

---

## Testing Strategy

72 tests, two layers:

* **Unit tests** (`test_attack.py`, `test_selector.py`, `test_orchestrator_fake.py`, `test_session.py`, `test_protocol.py`) run against `FakeProtocol` — a real in-memory `Protocol` implementation, not a mock library. Failure scenarios (a specific stage failing, a connection dropping at a specific point, a file unreadable mid-extraction) are scripted precisely and deterministically, including cases awkward to force reliably over a real socket.
* **Integration tests** (`test_integration_tcp.py`) spin up the actual compiled `simulator` binary as a subprocess on a free port and drive the real `TCPProtocol` over an actual socket — proving Part 1 and Part 2 work together, not just that each satisfies its interface in isolation.

**What integration testing caught that mocks couldn't:**

1. `Orchestrator.run()` originally closed the connection on every exit path including success, handing back a `Session` wired to a dead socket — invisible to mock tests, immediate once a real run tried to read a file afterward.
2. The phantom-drop bug (see Q4) — a fallback attack reusing the previous attack's dead socket.

**Coverage by area:** per-attack compatibility bounds and `IOSVersion` ordering; selector filtering / ranking / tie-break / empty queue; orchestrator clean success, stage-failure fallback, bounded drop-retry, crash-with-zero-retries, full exhaustion; protocol `READ` length-mismatch, `HELLO` field validation and defaults, malformed `LIST`; session locked-refusal, `extract_all()`, per-file failure isolation, drop/crash-mid-extraction → `.aborted`.

---

## Future Improvements & Next Steps

* **Dynamic / Learned Attack Probabilities:** Replace static per-stage success probabilities with a model trained on historical execution data (device model, OS version, battery, environmental factors). The `estimated_success_probability` property is the single injection point, and `orchestrator.attempts` already records data in the right shape.
* **Structured Binary Wire Protocol:** Transition from plain-text ASCII payloads (`STAGE 2`, `OK HELLO`) to a fully serialized binary protocol. Deliberately out of scope here — plain-text payloads keep the protocol inspectable in a packet capture; the length-prefix framing already made arbitrary binary content in `READ` safe.
* **Transport Layer Security & Authentication:** Add TLS encryption and mutual certificate/token authentication over the TCP socket for secure execution on real network/USB interfaces.

---

## Interview Questions & Prep Points

### 1. "Walk me through your solution end-to-end."

* *Verbal Outline:* Start with the `Orchestrator` connecting through a `Protocol` bridge and querying device state via `HELLO`. Explain how `AttackSelector` filters compatible attacks and ranks them (probability = product of stage probabilities, ties broken by fewer stages) into a fallback queue. Trace execution through `Attack.run()`, iterating `Stage` objects over the protocol, stopping at the first failure. A fully successful chain issues `UNLOCK` and returns an active `Session`; the caller then does best-effort data extraction via `Session.extract_all()` (`LIST` then `READ` per path). If the whole queue is exhausted, `NoViableAttackError` with a full audit trail on `orchestrator.attempts`.

### 2. "Why did you structure the project into pure Python and a C simulator?"

* *Verbal Outline:* Decoupling via the `Protocol` Bridge. Part 1 (`orchestrator/`) is pure Python decision logic, fully unit-testable in-memory via `FakeProtocol` — including failure scenarios (a specific stage dropping the connection) that are awkward to force reliably over a real socket. Part 2 (`simulator/`) is a small compiled C binary that exercises the real `TCPProtocol` over an actual socket, simulating stage outcomes, silent connection drops, and device crashes, so integration tests prove Part 1 and Part 2 genuinely work together.

### 3. "How do you distinguish between a network glitch and a device crash?"

* *Verbal Outline:* A silent socket closure with no response is a `ConnectionDropped` event — the client's read *fails*. That triggers a bounded retry of the same attack from stage 1, because it's likely transient (cable pull, bootloader hang). A device crash explicitly returns `ERR CRASH <id>` *before* closing — the client's read *succeeds*, and that successful read is the actual signal that tells a crash apart from a drop. It raises `DeviceCrashed`, a **sibling** class of `ConnectionDropped` (not a subclass), so it bypasses the retry loop entirely: abort the attack and move to the next candidate. Since the crash left the socket dead, the orchestrator reconnects proactively before that next candidate runs.

### 4. "What was a major bug or design challenge you uncovered during development?"

* *Verbal Outline:* The socket-inheritance bug, caught during TCP integration testing. When an attack failed after its connection-drop retries were exhausted, the next fallback attack reused the now-dead socket, so its very first stage instantly failed with a phantom connection drop — and with a tight retry budget, that phantom drop could exhaust a fully viable fallback attack's retries and fail the whole run. Fixed by a proactive reconnect in `Orchestrator.run()` before handing control to the next candidate. Regression test: `test_next_attack_gets_a_fresh_connection_after_retries_exhausted`. Invisible to any mock-based test; obvious the moment a real socket was involved.

### 5. "Give a concrete example where the selector has to choose between attacks."

* *Verbal Outline:* An `iPhone10,1` running iOS 14.4 with 60% battery. Both `checkm8_style` and `checkrain_style` are bootrom-based and compatible on that hardware/iOS/battery. The selector ranks by estimated success — `checkm8` at 0.812 (3 stages) beats `checkrain` at 0.654 (4 stages) — so `checkm8` runs first and `checkrain` is the fallback if any `checkm8` stage returns `FAIL`. Now flip `jailbroken` to true: `jailbreak_ssh_style` joins the queue at 0.951 and jumps to the front, because once a jailbreak already exists there's no reason to re-run an exploit chain. `agent_style` would only enter the picture above iOS 15.0 with ≥ 40% battery and AFU.

### 6. "Walk me through your wire protocol."

* *Verbal Outline:* Length-prefixed framing — 4-byte big-endian length, then that many payload bytes, both directions. Big-endian because it's network byte order and removes C/Python native-order ambiguity. Length-prefix rather than newline-delimited specifically because `READ` returns raw file bytes that can contain `\n` — the receiver takes content by length, never by scanning. Payloads are otherwise plain text (`STAGE 2`, `OK HELLO model=…`) so a packet capture stays readable; only `READ`'s reply is structured (header, one `\n`, raw bytes). Commands: `HELLO`, `STAGE <id>`, `UNLOCK`, `READ`, `LIST`, `QUIT`. The protocol carries three distinct failure signals — `FAIL` (device answered no), a silent socket close (read fails → transient), and `ERR CRASH <id>` then close (read succeeds → the exploit broke the device). Simulator behavior is set by CLI flags at startup, never over the wire.
