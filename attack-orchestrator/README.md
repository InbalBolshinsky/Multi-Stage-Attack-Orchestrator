# Multi-Stage Attack Orchestrator

A framework that, given a device, picks a compatible unlocking attack from
a registry of candidates, runs it stage by stage, and extracts data once
it succeeds. Part 1 (Python) is pure decision-making logic; Part 2 (C) is a
TCP-based device simulator it talks to; Part 3 is tests, including tests
that run the real Python client against the real compiled C simulator.

See [`PROTOCOL.md`](PROTOCOL.md) for the wire protocol between the two.

## Running it

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
  ├─ AttackSelector       filters compatible attacks, ranks by estimated success
  ├─ Attack (interface)   Composite of Stages; is_compatible(), run()
  │    ├─ Checkm8StyleAttack    (example: bootrom-level, old hardware, low battery floor)
  │    ├─ CheckrainStyleAttack  (example: full jailbreak on that same bootrom exploit, narrower device subset)
  │    └─ AgentStyleAttack      (example: sideloaded agent, newer iOS, higher battery floor)
  ├─ Stage (interface)    one step; declares an estimated success_probability
  ├─ Protocol (interface) Bridge: how communication actually happens
  │    ├─ FakeProtocol         in-memory, for Part 1 tests -- no network
  │    └─ TCPProtocol          real socket, speaks PROTOCOL.md to the C simulator
  ├─ AttackContext         shared state (protocol, device, scratch dict) passed to every Stage
  └─ Session               returned on success; read_file() / extract_all()
```

### Design patterns used, and why

**Strategy** — `Attack` and `Stage` are both interchangeable implementations
of a shared interface. The orchestrator, selector, and runner never need to
know which concrete attack/stage they're holding. This is the backbone
almost everything else hangs off.

**Composite** — an `Attack` is structurally "made of" an ordered list of
`Stage`s, and exposes a single `run()` over the whole chain — the same
shape a lone stage has from the caller's side.

**Bridge** — `Protocol` decouples "what an attack/stage needs to do"
(connect, run a stage, read a file) from "how that actually happens on the
wire" (in-memory fake vs. real TCP to the C simulator). Stages depend only
on the `Protocol` interface via `AttackContext`, never on a concrete
implementation — this is what makes Part 1 fully testable without Part 2
existing, and lets the exact same `Attack`/`Stage` code run against either
implementation unchanged.

**Considered and rejected: Chain of Responsibility** for running the stage
sequence. It's a structurally valid fit (each stage either "handles" the
request and passes it on, or halts the chain) — but CoR earns its
complexity when the chain needs to be assembled dynamically or stages need
to be decoupled from their neighbors at runtime. Here, an attack's stage
list is fixed and known at construction time, so a plain sequential loop
(`for stage in self.stages: ...`) gets identical behavior without the
extra `set_next()` wiring. Went with the simpler option.

**Considered and rejected: decision tree** for attack selection. Early on
this looked appealing ("pick an attack based on device state"), but
compatibility per attack is a flat conjunction of independent checks (model
in set? iOS in range? battery sufficient?) — there's no branching structure
that differs attack-to-attack to justify a tree. Went with filter-then-rank
instead (see below).

## The four things the assignment explicitly asks you to think about

### 1. Several attacks may be valid — how do you pick?

Two-phase: **filter** attacks down to ones compatible with the device
(`Attack.is_compatible()`), then **rank** the survivors by
`estimated_success_probability` (the product of each stage's declared
probability — a chain only succeeds end-to-end if every stage does).

The `AttackSelector` returns this ranking as an ordered queue rather than a
single pick, because that queue is what makes the fallback behavior in §3
possible: if the top candidate fails, the orchestrator doesn't give up, it
tries the next one down the list.

Ties are broken by fewer stages first — a shorter chain has fewer places to
fail and costs less time to attempt, which seemed like a reasonable
default; this is called out explicitly in code as a judgment call rather
than a "correct" answer. `test_ties_broken_by_fewer_stages` in
`test_selector.py` isolates this rule with two minimal synthetic attacks
built to have an exact probability tie (0.5 × 0.5 == 0.25, exactly
representable in binary floating point) rather than contorting the real
example attacks' realistic numbers to coincide.

### 2. What should an attack check before it runs?

`DeviceState` carries `model`, `ios_version`, `battery`, and `locked`.
These weren't picked arbitrarily — they're grounded in how real mobile
forensic tooling actually gates low-level extraction attempts:

- **model / chipset generation** — exploits target specific hardware
  generations, not just "an iPhone"
- **iOS version, compared numerically by point release** — not just major
  version; an exploit viable on 15.7 may be patched by 16.0. (See
  `IOSVersion` in `device.py` — a naive string comparison would sort "9.0"
  after "15.0", which is wrong.)
- **battery** — insufficient charge is a commonly-cited real reason a
  low-level attack attempt can't even be started; different attack styles
  have different floors (a bootrom-level exploit needs far less charge than
  one requiring the device to stay powered through a sideload + reboot)

`locked` is tracked but isn't a compatibility gate — an attack's whole job
is to get from locked to unlocked, so it wouldn't make sense to require
`locked=False` as a precondition.

### 3. Stages fail — what does that mean for the rest of the chain?

The chain distinguishes **three different failure modes**, because they
warrant different handling:

- **Stage-logic failure** (the device responded, the stage just didn't
  succeed) → abort this attack, fall through to the next attack in the
  selector's queue. A logical failure means this exploit doesn't apply or
  work against this specific device — retrying the identical stage against
  an unchanged device state isn't expected to produce a different result,
  so the orchestrator doesn't retry in place. It *does* try a different
  attack, which is exactly what the assignment's "several may be valid"
  framing sets up.

- **Connection dropped mid-chain** (the socket died, not a device
  response) → transient/environmental, not a verdict on the exploit
  itself. The orchestrator reconnects and retries **the same attack from
  the start**, bounded by `max_connection_retries`. Retrying from the
  start rather than resuming mid-chain is deliberate: a partially-applied
  low-level exploit can leave a device in a state the framework can't
  safely reason about, so it prefers a clean re-attempt over resuming
  blind — this mirrors how real bootloader-exploit tooling favors starting
  from a known-clean state over continuing after a failed attempt.

- **Device crashed mid-chain** (`DeviceCrashed`, the wire protocol's `ERR
  CRASH <id>`) → the device got to explicitly report that this stage broke
  it, before the connection closed. This looks similar to a dropped
  connection at the socket level (the connection ends up dead either way)
  but means the opposite thing: it's not transient/environmental, it's a
  verdict on the exploit — this stage crashes this device. So it gets the
  **stage-logic-failure treatment**, not the drop's reconnect-and-retry:
  abort this attack, fall through to the next one, no retry of the same
  attack. `DeviceCrashed` is deliberately a *sibling* of `ConnectionDropped`
  in the exception hierarchy (not a subclass) specifically so that nothing
  catching `ConnectionDropped` broadly can accidentally catch a crash too
  and apply the wrong policy to it.

If the queue of compatible attacks is exhausted without success (whether
by logic failures, crashes, or connection retries running out), `run()`
raises `NoViableAttackError` with a full audit trail available on
`orchestrator.attempts`.

### 4. From "read one file" to "extract everything"

`Session.read_file(path)` is the one guaranteed primitive.
`Session.extract_all()` is built on top of it via `Protocol.list_files()`
(a `LIST` command added to the protocol, since Part 2's design was ours to
make) — the device enumerates extractable paths, and extraction pulls each
one.

Two decisions worth calling out:

- **Extraction accepts an explicit path list too** (`Session.extract(paths)`),
  not just full auto-discovery — so extraction still works against a
  device/profile that can only do single-file reads against a known
  manifest, without requiring `LIST` to exist.
- **Extraction is per-file best-effort, not all-or-nothing.** One missing
  or unreadable file doesn't discard everything else that succeeded —
  `ExtractionResult` separately tracks `.files` (succeeded) and `.errors`
  (failed, with a reason), so a caller gets everything that was actually
  recoverable rather than nothing at all because of one bad path.

## Testing strategy

- **Unit tests** (`test_attack.py`, `test_selector.py`,
  `test_orchestrator_fake.py`, `test_session.py`) run against
  `FakeProtocol` — a real Python object implementing the `Protocol`
  interface entirely in memory, not a mock library. This lets failure
  scenarios (a specific stage failing, a connection dropping at a specific
  point) be scripted precisely and deterministically, including scenarios
  that would be awkward to force reliably over a real socket (e.g. "drop
  exactly once, then succeed on reconnect").
- **Integration tests** (`test_integration_tcp.py`) spin up the actual
  compiled `simulator` binary as a subprocess on a free port and drive the
  real `TCPProtocol` against it over an actual socket — proving Part 1 and
  Part 2 genuinely interoperate, per the protocol in `PROTOCOL.md`, not
  just that each satisfies its own interface in isolation. This is also
  what caught a real bug during development: `Orchestrator.run()`
  originally closed the connection on every exit path including success,
  handing back a `Session` wired to a dead socket — invisible to any
  mock-based test, immediately visible once a real successful run tried to
  actually read a file afterward.

Scenarios covered: clean success; stage-failure fallback to a second
compatible attack; exhaustion when no attack is compatible; exhaustion when
every compatible attack fails; a persistent connection drop correctly
bounded by retry count (both against `FakeProtocol`, scripted precisely,
and against the real simulator's `--drop-stage`); a device crash falling
straight through to the next attack with **zero** reconnect attempts,
proving it gets the stage-logic-failure policy rather than the drop's
retry policy (again both against `FakeProtocol` and the real simulator's
`--crash-stage`); a simulator-level sanity check that `READ` is refused
before any attack unlocks the device; and, in `test_selector.py`, the
three-attack case where two bootrom-based attacks (`checkm8_style`,
`checkrain_style`) are simultaneously compatible on shared hardware and get
ranked by estimated probability, plus an isolated check (via two minimal
synthetic attacks, not the real examples) that a probability tie is broken
by fewer stages.

## What's deliberately out of scope

- Learning/updating attack success probabilities from historical run data —
  the current model uses statically declared per-stage estimates, which is
  appropriate for the scope here but is the natural next step for a
  production version.
- A binary encoding for command/response *payloads* — framing is now
  length-prefixed (see `PROTOCOL.md`), which is what actually made
  arbitrary binary content in `READ` safe, but each payload's contents are
  still a plain text string (`"STAGE 2"`, `"OK HELLO ..."`, etc.) rather
  than a structured binary format. That keeps the protocol inspectable in
  a log/packet-capture without inventing a binary encoding for every
  command's arguments — a deliberate scope line, not an oversight.
