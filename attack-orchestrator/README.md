# Multi-Stage Attack Orchestrator

A framework that, given a mobile device, picks a compatible unlocking attack from a registry of candidates, runs it stage by stage, and extracts data once it succeeds.

* **Part 1** (`orchestrator/`): pure Python decision-making: which attack to run, how to react when a stage fails, how to turn a successful chain into extracted files.
* **Part 2** (`simulator/`): a device simulator written in C, spoken to over TCP, that behaves enough like a real device to exercise Part 1 properly, including when things go wrong .
* **Part 3** (`tests/`): tests for both, including integration tests that run the real Python client against the real compiled C simulator, not just in-memory fakes.

## Quick start

```bash
# Build the simulator
cd simulator && make && cd ..

# Run the test suite (unit tests + integration tests against the real
# compiled simulator binary)
pip install pytest --break-system-packages   # or use a venv
python3 -m pytest -v

# Try it manually
./simulator/simulator --port 9000 --model iPhone8,1 --ios 14.4 --battery 60 &
python3 -c "
from orchestrator import AttackSelector, Orchestrator, TCPProtocol
from orchestrator.attacks import all_attacks

proto = TCPProtocol('127.0.0.1', 9000)
orch = Orchestrator(proto, AttackSelector(all_attacks()))
session = orch.run()
print(session.extract_all().succeeded)
session.close()
"

```

## Architecture

```
Orchestrator
  ├─ AttackSelector
  │ 
  ├─ Attack (interface)   
  │    ├─ Checkm8StyleAttack  
  │    ├─ CheckrainStyleAttack  
  │    ├─ AgentStyleAttack  
  │    └─ JailbreakSSHStyleAttack
  │
  ├─ Stage (interface)
  │
  ├─ Protocol (interface) Bridge: how communication actually happens
  │    ├─ FakeProtocol   
  │    └─ TCPProtocol
  │  
  ├─ AttackContext
  │  
  └─ Session

```

### Design patterns used, and why

**Strategy:** `Attack` and `Stage` are both interchangeable implementations of a shared interface. The orchestrator, selector, and runner never need to know which concrete attack/stage they're holding. This is the backbone almost everything else hangs off.

**Composite:** an `Attack` is structurally "made of" an ordered list of `Stage`s, and exposes a single `run()` over the whole chain - the same shape a lone stage has from the caller's side.

**Bridge:** `Protocol` decouples "what an attack/stage needs to do" (connect, run a stage, read a file) from "how that actually happens on the wire" (in-memory fake vs. real TCP to the C simulator). Stages depend only on the `Protocol` interface via `AttackContext`, never on a concrete implementation - this is what makes Part 1 fully testable without Part 2 existing, and lets the exact same `Attack`/`Stage` code run against either implementation unchanged.

**Considered and rejected: Chain of Responsibility** for running the stage sequence. It's a structurally valid fit (each stage either "handles" the request and passes it on, or halts the chain) - but CoR earns its complexity when the chain needs to be assembled dynamically or stages need to be decoupled from their neighbors at runtime. Here, an attack's stage list is fixed and known at construction time, so a plain sequential loop (`for stage in self.stages: ...`) gets identical behavior without the extra `set_next()` wiring. So I went with the simpler option.

**Considered and rejected: decision tree** for attack selection. Early on this looked appealing ("pick an attack based on device state"), but compatibility per attack is a flat conjunction of independent checks (model in set? iOS in range? battery sufficient? AFU/BFU? jailbroken?) - there's no branching structure that differs attack-to-attack to justify a tree. So I went with filter-then-rank instead (see below).

## Design decisions

The assignment calls out four things worth thinking about. Here's how each was resolved, and why, where more than one reasonable option existed.

### 1. Several attacks may be valid: how do you pick?

Two-phase: **filter** attacks down to ones compatible with the device (`Attack.is_compatible()`), then **rank** the survivors by `estimated_success_probability` (the product of each stage's declared probability - a chain only succeeds end-to-end if every stage does).

`AttackSelector.build_queue()` returns this ranking as an ordered queue rather than a single pick, because that queue is what makes the fallback behavior in section #3 possible: if the top candidate fails, the orchestrator doesn't give up, it tries the next one down the list.

Ties are broken by fewer stages first: a shorter chain has fewer places to fail and costs less time to attempt, which seemed like a reasonable default- this is called out explicitly in code as a judgment call rather than a "correct" answer. `test_ties_broken_by_fewer_stages` in `test_selector.py` isolates this rule with two minimal synthetic attacks built to have an exact probability tie (0.5 × 0.5 == 0.25, exactly representable in binary floating point) rather than twisting the real example attack's realistic numbers to coincide.

### 2. What should an attack check before it runs?

`DeviceState` carries:

* `model`
* `ios_version`
* `battery`
* `locked`
* `after_first_unlock`
* `jailbroken`

These weren't picked arbitrarily - they're grounded in my research done on how real mobile forensic tooling actually gates low-level extraction attempts:

* **model / chipset generation:** Exploits target specific hardware generations, not just "an iPhone"
* **iOS version, compared numerically by point release:** Not just major version; an exploit viable on 15.7 may be patched by 16.0. (See `IOSVersion` in `device.py` - a naive string comparison would sort "9.0" after "15.0", which is wrong.)
* **battery:** Insufficient charge is a commonly-cited real reason a low-level attack attempt can't even be started. Different attack styles have different floors (a bootrom-level exploit needs far less charge than one requiring the device to stay powered through a sideload and reboot)
* **AFU / BFU** (`after_first_unlock`): Whether the passcode has been entered since last boot. Independent of `locked`: a device can be AFU but currently re-locked at the lock screen. Some attacks require one state specifically (`AgentStyleAttack` requires AFU, since sideloading needs pairing/keychain state that only exists post-unlock)
* **jailbroken:** Whether the device already has a working jailbreak from a prior run. `JailbreakSSHStyleAttack` requires this and skips exploiting entirely, riding the existing jailbreak over SSH instead

`locked` is tracked but isn't a compatibility gate - an attack's whole job is to get from locked to unlocked, so it wouldn't make sense to require `locked=False` as a precondition.

### 3. Stages fail: what does that mean for the rest of the chain?

The chain distinguishes **three different failure modes**, because they warrant different handling:

* **Stage-logic failure** (the device responded, the stage just didn't succeed) → abort this attack, fall through to the next attack in the selector's queue. A logical failure means this exploit doesn't apply or work against this specific device, and retrying the identical stage against an unchanged device state isn't expected to produce a different result, so the orchestrator doesn't retry in place. It does try a different attack, which is exactly what the assignment's "several may be valid" framing sets up.
* **Connection dropped mid-chain** (the socket died, not a device response) → transient/environmental, not a verdict on the exploit itself. The orchestrator reconnects and retries **the same attack from the start**, bounded by `max_connection_retries`. Retrying from the start rather than resuming mid-chain is deliberate: a partially-applied low-level exploit can leave a device in a state the framework can't safely reason about, so it prefers a clean re-attempt over resuming blind - this mirrors how real bootloader-exploit tooling favors starting from a known-clean state over continuing after a failed attempt.
* **Device crashed mid-chain** (`DeviceCrashed`, the wire protocol's `ERR CRASH <id>`) → the device got to explicitly report that this stage broke it, before the connection closed. This looks similar to a dropped connection at the socket level (the connection ends up dead either way) but means the opposite thing: it's not transient/environmental, it's a verdict on the exploit - this stage crashes this device. So it gets the **stage-logic-failure treatment**, not the drop's reconnect-and-retry: abort this attack, fall through to the next one, no retry of the same attack. `DeviceCrashed` is deliberately a *sibling* of `ConnectionDropped` in the exception hierarchy (not a subclass) specifically so that nothing catching `ConnectionDropped` broadly can accidentally catch a crash too and apply the wrong policy to it.

Falling through to the next attack in the queue always starts that attack on a known-good connection. A crash or an exhausted run of drop-retries both leave the socket dead, so before handing the next candidate its turn, `Orchestrator.run()` reconnects proactively (skipped if there's no next candidate to give a fair shot to, or if the connection is still alive, e.g. an ordinary stage-logic failure). Without this, the next attack's own first stage-send would discover the dead socket itself and get its *own* connection drop reported against it - misattributing the previous attack's dead connection as a fresh failure of an attack that was never actually tried, and in the worst case (a tight retry budget) burning that attack's retries on a phantom drop instead of a real attempt.

If the queue of compatible attacks is exhausted without success (whether by logic failures, crashes, or connection retries running out), `run()` raises `NoViableAttackError` with a full audit trail available on `orchestrator.attempts`.

### 4. From "read one file" to "extract everything"

`Session.read_file(path)` is the one guaranteed primitive. `Session.extract_all()` is built on top of it via `Protocol.list_files()` (a `LIST` command added to the protocol, since Part 2's design was mine to make) - the device enumerates extractable paths, and extraction pulls each one.

Two decisions worth calling out:

* **Extraction accepts an explicit path list too** (`Session.extract(paths)`), not just full auto-discovery - so extraction still works against a device/profile that can only do single-file reads against a known manifest, without requiring `LIST` to exist.
* **Extraction is per-file best-effort, not all-or-nothing.** A missing or unreadable file (`ERR NOTFOUND`, `ERR LOCKED`) is recorded in `ExtractionResult.errors` and extraction keeps going, so a caller gets everything actually recoverable rather than nothing because of one bad path. A connection drop or device crash mid-extraction is different - the channel itself is gone, so the loop stops immediately and that's recorded once in `ExtractionResult.aborted` instead of as another per-file error.

## Part 2: device simulator & wire protocol

The simulator (`simulator/simulator.c`) stands in for a real device over TCP: it reports device info, "runs" attack stages with configurable success/failure, and once "unlocked" serves reads from a small in-memory fake filesystem. It also simulates the two ways a real device attempt can go wrong beyond a plain stage failure: a silent connection drop and a device crash. Since a device simulator that can only succeed or return `FAIL` wouldn't exercise section #3 above at all. The protocol itself was ours to design.

**Framing.** Every message, either direction, is one frame: `[4 bytes: payload length, big-endian uint32][N bytes: payload]`. Big-endian because that's network byte order - the standard every real protocol uses, and it removes any ambiguity between C and Python defaulting to different native byte order. The receiver always knows exactly how many payload bytes follow, so framing never depends on scanning for a delimiter, which matters because `READ`'s reply embeds raw file bytes that can contain any byte value, including `\n`. A zero-length frame, an oversized declared length, or a connection that dies mid-frame are all treated as protocol errors - no real message is ever empty.

Payload *content* is still plain text for every command and most responses - only the framing changed. `READ`'s reply is the one place a payload has structure: a text header, one embedded `\n`, then the raw file bytes filling out the rest of the frame. The receiver splits on the *first* `\n` only and takes everything after it by length, so an embedded `\n` inside the file content is not a problem.

**Commands (client → server):**

| Command | Purpose |
| --- | --- |
| `HELLO` | Ask for device info |
| `STAGE <id>` | Execute one attack stage by numeric id |
| `UNLOCK` | Mark the device unlocked (sent after all stages in a chain succeed) |
| `READ <path>` | Read one file (only valid once unlocked) |
| `LIST` | Enumerate extractable file paths (only valid once unlocked) |
| `QUIT` | Close the session cleanly |

**Responses (server → client):**

| Response | Meaning |
| --- | --- |
| `OK HELLO model=<m> ios=<v> battery=<0-100> locked=<0|1> afu=<0|1> jailbroken=<0|1>` | device info |
| `OK STAGE <id> SUCCESS` / `OK STAGE <id> FAIL` | stage outcome |
| `ERR CRASH <id>` | the device reports that stage crashed it, then the connection closes |
| `OK UNLOCK locked=0` | unlock acknowledged |
| `OK READ <path> <len>\n<raw bytes>` | file content, one frame |
| `OK LIST <n>\n<path 1>\n...\n<path n>` | file listing, one frame |
| `OK BYE` | ack for `QUIT` |
| `ERR LOCKED` | `READ`/`LIST` requested before any attack unlocked the device |
| `ERR NOTFOUND <path>` | requested path doesn't exist |
| `ERR UNKNOWN <command>` | unrecognized command |

Notes:

* `afu` is 1 if the passcode has been entered since the device's last boot, independent of `locked` (see section #2 above). `jailbroken` is 1 if the device already has a working jailbreak, independent of both.
* A **dropped connection is silent** : No `ERR` reply, the socket just closes at a frame boundary. This deliberately mirrors a real device failure (cable pull, bootloader hang) rather than a clean protocol-level error, so the client can tell "the device told me no" (`ERR`/`FAIL`) apart from "the device just vanished" (closed socket) - see section #3 for why that distinction drives different retry behavior.
* `ERR CRASH <id>` is a third failure mode: the device gets a chance to report that this stage broke it, and only then does the connection close. The client's read of this reply succeeding is the actual signal that tells a crash apart from a silent drop, where the read itself fails.
* `<byte-length>` in the `READ` header is redundant with the frame's own length prefix - it's kept for readability/logging, not needed to parse the frame correctly.

**Simulator configuration** is via CLI flags at startup, not over the wire: "what should this fake device do" is a test-setup concern, not something a real device would expose to an attacker:

```bash
./simulator --port 9000 --model iPhone8,1 --ios 14.4 --battery 60 \
    --fail-stage 2 --fail-stage 5 --drop-stage 7 --crash-stage 3 --bfu --jailbroken

```

| Flag | Effect |
| --- | --- |
| `--port <n>` | listen port (default 9000) |
| `--model / --ios / --battery` | what `HELLO` reports |
| `--fail-stage <id>` (repeatable) | that stage always returns `FAIL` |
| `--drop-stage <id>` | connection is silently closed when that stage is requested |
| `--crash-stage <id>` | that stage replies `ERR CRASH <id>`, then the connection closes |
| `--bfu` | report `afu=0` (default is AFU, the more common case) |
| `--jailbroken` | report `jailbroken=1` (default is stock) |

## Testing strategy

* **Unit tests** (`test_attack.py`, `test_selector.py`, `test_orchestrator_fake.py`, `test_session.py`, `test_protocol.py`) run against `FakeProtocol`: A real Python object implementing the `Protocol` interface entirely in memory, not a mock library. This lets failure scenarios (a specific stage failing, a connection dropping at a specific point) be scripted precisely and deterministically, including scenarios that would be awkward to force reliably over a real socket.
* **Integration tests** (`test_integration_tcp.py`) spin up the actual compiled `simulator` binary as a subprocess on a free port and drive the real `TCPProtocol` against it over an actual socket - proving Part 1 and Part 2 genuinely work together, not just that each satisfies its own interface in isolation. This is also what caught a real bug during development: `Orchestrator.run()` originally closed the connection on every exit path including success, handing back a `Session` wired to a dead socket - invisible to any mock-based test, immediately visible once a real successful run tried to actually read a file afterward. It also caught a second one the same way: falling through to a fallback attack after a persistent `--drop-stage` reused the previous attack's now-dead socket, so the fallback attack's first stage misreported a connection drop against itself - with a tight retry budget, that phantom drop could exhaust the fallback attack's retries and fail the whole run even though the fallback attack was fully viable. Fixed by reconnecting before handing the next candidate its turn (see section #3 above): `test_next_attack_gets_a_fresh_connection_after_retries_exhausted` is the regression test.

Scenarios covered, roughly by file:

* **`test_attack.py`**:
* Per-attack compatibility bounds (model/iOS/battery/AFU-BFU/jailbroken) for each of the four example attacks
* `IOSVersion` numeric ordering
* `estimated_success_probability` as the product of stage probabilities


* **`test_selector.py`**:
* Filtering out incompatible attacks
* The three-attack case where two bootrom-based attacks (`checkm8_style`, `checkrain_style`) are simultaneously compatible on shared hardware and get ranked by estimated probability
* `jailbreak_ssh_style` joining and ranking first once the device reports jailbroken
* An empty queue when nothing is compatible
* An isolated check (via two minimal synthetic attacks, not the real examples) that a probability tie is broken by fewer stages


* **`test_orchestrator_fake.py`**:
* Clean success returning a working session
* Stage-failure fallback to the next compatible attack with no retry of the failed stage
* A persistent connection drop reconnecting and retrying up to `max_connection_retries` before giving up
* A device crash falling straight through to the next attack with **zero** reconnect attempts (proving it gets the stage-logic-failure policy, not the drop's retry policy)
* Exhaustion, both when no attack is compatible at all and when every compatible attack fails


* **`test_protocol.py`**:
* `READ` length-mismatch detection
* `HELLO` field validation and its backward-compatible defaults for `afu`/`jailbroken`
* Malformed `LIST` counts


* **`test_session.py`**:
* Reading a file once unlocked vs. a locked refusal
* `extract_all()` pulling every discoverable file
* A per-file failure not discarding already-successful extractions
* A connection drop or device crash mid-extraction aborting the loop and being recorded in `.aborted` rather than as a per-file error


* **`test_integration_tcp.py`**:
* The same fallback/drop/crash scenarios above, driven over a real socket against the real compiled simulator (via `--fail-stage`/`--drop-stage`/`--crash-stage`)
* A simulator-level sanity check that `READ` is refused before any attack unlocks the device



## What's deliberately out of scope

* **Learning/updating attack success probabilities from historical run data:** The current model uses statically declared per-stage estimates, which is appropriate for the scope here but is the natural next step for a production version - e.g. a model trained on historical per-stage outcomes (device model, iOS version, battery, etc.) to replace the static probabilities with learned ones.
* **A binary encoding for command/response payloads:** Framing is now length-prefixed, which is what actually made arbitrary binary content in `READ` safe, but each payload's contents are still a plain text string (`"STAGE 2"`, `"OK HELLO ..."`, etc.) rather than a structured binary format. That keeps the protocol inspectable in a log/packet-capture without inventing a binary encoding for every command's arguments - a deliberate scope line, not an oversight.
* **Transport encryption/authentication:** The protocol is plaintext over a bare TCP socket, so anyone on the network path can read or inject commands. Fine for talking to a local simulator in this exercise, but a real deployment would need this on a wire actually reaching a device (e.g. TLS, or an authenticated channel over USB).
