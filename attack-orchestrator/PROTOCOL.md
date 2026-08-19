# Protocol

A small line-based text protocol over TCP between the Python orchestrator
(client) and the C device simulator (server). Text was chosen over a binary
format because it's trivial to log, debug with `nc`/`telnet`, and read in a
packet capture — none of which was worth trading away for the small
efficiency gain of a binary encoding at this scale.

One client is served at a time: the simulator accepts a connection, serves
it to completion (or until it drops/QUITs), then accepts the next. This
matches how the orchestrator actually uses it — one attack attempt, one
connection.

Every line is terminated with `\n`. The server strips trailing `\r` if
present, so it's tolerant of either line ending.

## Commands (client → server)

| Command | Purpose |
|---|---|
| `HELLO` | Ask for device info |
| `STAGE <id>` | Execute one attack stage by numeric id |
| `UNLOCK` | Mark the device unlocked (sent after all stages in a chain succeed) |
| `READ <path>` | Read one file (only valid once unlocked) |
| `LIST` | Enumerate extractable file paths (only valid once unlocked) |
| `QUIT` | Close the session cleanly |

## Responses (server → client)

```
OK HELLO model=<model> ios=<version> battery=<0-100> locked=<0|1>
OK STAGE <id> SUCCESS
OK STAGE <id> FAIL
OK UNLOCK locked=0
OK READ <path> <byte-length>
<raw file content, one line>
OK LIST <n>
<path 1>
<path 2>
...
<path n>
OK BYE
ERR LOCKED
ERR NOTFOUND <path>
ERR UNKNOWN <command>
```

Notes:
- `READ`'s response is two lines: a header line with the byte length,
  followed by the raw content itself on the next line. Content in this
  simulator is placeholder text, not real binary blobs, so a newline-safe
  raw write is sufficient; a production version would need a
  length-prefixed binary frame instead of relying on a trailing newline for
  arbitrary binary content.
- A dropped connection is *silent* — no `ERR` line, the socket just closes.
  This deliberately mirrors a real device failure (crash, cable pull,
  bootloader hang) rather than a clean protocol-level error, since the
  orchestrator has to be able to tell the difference between "the device
  told me no" (`ERR`/`FAIL`) and "the device just vanished" (closed
  socket) — see the README section on failure handling for why that
  distinction drives different retry behavior.

## Simulator configuration (not part of the wire protocol)

The simulator's behavior is configured via CLI flags at startup, not over
the wire, since "what should this fake device do" is a test-setup concern,
not something a real device would expose to an attacker:

```
./simulator --port 9000 --model iPhone8,1 --ios 14.4 --battery 60 \
    --fail-stage 2 --fail-stage 5 --drop-stage 7
```

- `--fail-stage <id>` (repeatable): that stage always returns `FAIL`
- `--drop-stage <id>`: the connection is silently closed when that stage is requested
- device info flags (`--model`, `--ios`, `--battery`) control what `HELLO` reports
