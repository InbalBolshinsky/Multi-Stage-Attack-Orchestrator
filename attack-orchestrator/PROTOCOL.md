# Protocol

A small length-prefixed text-payload protocol over TCP between the Python
orchestrator (client) and the C device simulator (server).

## Framing

Every message, either direction, is one frame:

```
[4 bytes: payload length, big-endian unsigned int] [N bytes: payload]
```

Big-endian because that's "network byte order" -- the standard every real
protocol uses, and it removes any ambiguity between C and Python defaulting
to different native byte order. C uses `htonl()`/`ntohl()`; Python uses
`int.to_bytes(4, "big")`/`int.from_bytes(data, "big")`.

The receiver always knows exactly how many payload bytes follow, so framing
never depends on scanning for a delimiter character. This matters because
payload content -- in particular the raw file bytes in a `READ` reply --
can contain any byte value, including `\n`, without corrupting the framing.
(An earlier version of this protocol was line-based, terminating each
message with `\n`; that made a `\n` byte inside file content ambiguous with
the end of the message. Switching to explicit length-prefixing was a
deliberate fix for that hole, not just a stylistic change.)

The payload itself is still plain text for every command and most
responses -- only the framing changed, not the command vocabulary. `READ`'s
reply is the one place a payload has structure: a text header, one
embedded `\n`, then the raw file bytes making up the rest of the frame (see
below). The receiver splits on the *first* `\n` only and takes everything
after it by length, not by looking for a second delimiter, so an embedded
`\n` inside the file content itself is not a problem.

Zero-length frames are not a valid message (no command or reply is ever
empty) and are treated as a protocol error, same as an oversized declared
length or a connection that dies mid-frame.

## Commands (client → server payload)

| Command | Purpose |
|---|---|
| `HELLO` | Ask for device info |
| `STAGE <id>` | Execute one attack stage by numeric id |
| `UNLOCK` | Mark the device unlocked (sent after all stages in a chain succeed) |
| `READ <path>` | Read one file (only valid once unlocked) |
| `LIST` | Enumerate extractable file paths (only valid once unlocked) |
| `QUIT` | Close the session cleanly |

## Responses (server → client payload)

```
OK HELLO model=<model> ios=<version> battery=<0-100> locked=<0|1>
OK STAGE <id> SUCCESS
OK STAGE <id> FAIL
ERR CRASH <id>
OK UNLOCK locked=0
OK READ <path> <byte-length>\n<raw file content>
OK LIST <n>\n<path 1>\n<path 2>\n...\n<path n>
OK BYE
ERR LOCKED
ERR NOTFOUND <path>
ERR UNKNOWN <command>
```

Notes:
- `READ`'s reply is a single frame: a header line (`OK READ <path>
  <byte-length>`), one `\n`, then the raw content -- not a separate frame.
  The frame's own length prefix already tells the receiver exactly how
  much content follows, so `<byte-length>` in the header is redundant
  information kept for readability/logging, not something the receiver
  needs to parse the frame correctly.
- `LIST`'s reply is likewise a single frame with paths joined by `\n`
  (no trailing `\n` -- the frame length marks the end).
- A dropped connection is *silent* -- no `ERR` reply, the socket just
  closes (a clean close at a frame boundary, i.e. before any bytes of the
  next frame's length prefix arrive). This deliberately mirrors a real
  device failure (cable pull, bootloader hang -- something with no
  opportunity to report anything) rather than a clean protocol-level
  error, since the orchestrator has to be able to tell the difference
  between "the device told me no" (`ERR`/`FAIL`) and "the device just
  vanished" (closed socket) -- see the README section on failure handling
  for why that distinction drives different retry behavior. A close that
  happens *mid-frame* (after the length prefix but before all its payload
  bytes arrive) is likewise treated as a dropped connection, not a
  malformed message -- both sides just stop.
- `ERR CRASH <id>` is a *third* failure mode, distinct from both an
  ordinary `FAIL` and a silent drop: the device gets a chance to report
  that running this stage broke it, and only *then* the connection
  closes (same as a `--drop-stage`, just with a reply sent first). The
  client's read of this reply succeeds -- that's the actual signal that
  distinguishes a crash from a silent drop, where the read itself is what
  fails. See the README section on failure handling for why a crash gets
  its own no-retry policy rather than being treated as either a plain
  stage failure or a transient drop.

## Simulator configuration (not part of the wire protocol)

The simulator's behavior is configured via CLI flags at startup, not over
the wire, since "what should this fake device do" is a test-setup concern,
not something a real device would expose to an attacker:

```
./simulator --port 9000 --model iPhone8,1 --ios 14.4 --battery 60 \
    --fail-stage 2 --fail-stage 5 --drop-stage 7 --crash-stage 3
```

- `--fail-stage <id>` (repeatable): that stage always returns `FAIL`
- `--drop-stage <id>`: the connection is silently closed when that stage is requested
- `--crash-stage <id>`: that stage replies `ERR CRASH <id>`, then the connection closes
- device info flags (`--model`, `--ios`, `--battery`) control what `HELLO` reports
