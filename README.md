# Protocol Layer (Member 2) — read this before using it

The wire framing layer is **done, compiled warning-free, and unit-tested**
(154 assertions, all passing, also clean under AddressSanitizer + UBSan).

## What you get

| File | What it is |
|---|---|
| `protocol.h` | Everything you call. Read the comments, they are the API docs. |
| `protocol.cpp` | Implementation. You should not need to open this. |
| `common_types.h` | The group's shared header contract (Phase 0). |
| `test_protocol.cpp` | Member 2's standalone test. Not part of the submission build. |
| `Makefile` | Builds/runs the test only. Not one of the four submission Makefiles. |

## The one rule

There is exactly **one master copy**, in `_protocol_master/`.
`Part1/`, `Part2_Case1/`, `Part2_Case2/` and `Part2_Case2_Enhanced/` each hold
a generated copy so that every folder builds on its own.

**Never edit `Part1/protocol.cpp` or any other copy directly.**
Edit `_protocol_master/protocol.cpp`, then from the project root run:

```bash
./sync_protocol.sh
```

It pushes the master into all four folders and re-checks that each copy still
compiles with zero warnings.

## How to send a message

Don't build payloads by hand. Every opcode has a one-line sender:

```cpp
#include "protocol.h"

send_get(fd, "Cane");                                   // 0x01
send_get_ok(fd, session_id, file_count, total_bytes);   // 0x02
send_error(fd, ERR_TOPIC_NOT_FOUND, "TOPIC_NOT_FOUND"); // 0x03
send_file_begin(fd, idx, offset, bytes_following, name);// 0x04
send_file_data(fd, idx, offset, buf, len);              // 0x05
send_file_end(fd, idx);                                 // 0x06
send_transfer_end(fd, files_sent, useful_bytes);        // 0x07
send_checkpoint_ack(fd, sid, idx, ack_offset);          // 0x08
send_resume(fd, sid, idx, offset, topic, filename);     // 0x09
send_resume_ok(fd, idx, accepted, rem_files, rem_bytes);// 0x0A
send_restart(fd, ERR_SESSION_EXPIRED, "SESSION_EXPIRED");//0x0B
send_get_enhanced(fd, 4, topic);                        // 0x0C
send_join_session(fd, sid, conn_id, bitmap, bmap_len);  // 0x0D
send_assign_work(fd, conn_id, idx, offset, chunk_len);  // 0x0E
```

All of them return `0` on success, `-1` if the socket is gone.

## How to receive a message

Always this shape — read the frame, switch on the opcode, then parse:

```cpp
FrameHeader hdr;
std::vector<uint8_t> payload;

int rc = recv_frame(fd, &hdr, payload);

if (rc == FRAME_EOF) {
    // peer closed cleanly with no message pending
} else if (rc == FRAME_SOCK_ERR) {
    // connection dropped — THIS is what a fault injection looks like
} else if (rc == FRAME_PROTO_ERR) {
    // garbage on the wire, close the connection
} else {                      // rc == FRAME_OK
    switch (hdr.type) {
    case OP_FILE_DATA: {
        MsgFileData m;
        if (!parse_file_data(payload.data(), hdr.payload_length, &m)) {
            // malformed payload — treat exactly like FRAME_PROTO_ERR
            break;
        }
        // use m.file_index, m.offset, m.data
        break;
    }
    // ... other opcodes
    }
}
```

### The four return codes matter

| Code | Meaning | What you normally do |
|---|---|---|
| `FRAME_OK` (1) | good frame | parse it |
| `FRAME_EOF` (0) | clean close, nothing pending | transfer finished or peer quit |
| `FRAME_SOCK_ERR` (-1) | dropped mid-stream | **reconnect / retry path** |
| `FRAME_PROTO_ERR` (-2) | bad magic, bad version, or payload > 1 MB | close, do not retry |

A fault injected by the server in the middle of a chunk shows up as
`FRAME_SOCK_ERR`, not `FRAME_EOF`. Case 1's retry loop and Case 2's resume
logic both hang off that distinction, so don't collapse the two.

## Notes per member

- **Member 1** — `send_all` / `recv_all` already retry on `EINTR`, so your
  signal handler for graceful shutdown won't corrupt an in-flight frame.
- **Member 3** — call `should_inject_fault()` *after* `send_file_data()`
  returns 0. The client will see `FRAME_SOCK_ERR`.
- **Member 4** — `zero_session_id()`, `session_id_to_hex()` and
  `hex_to_session_id()` are in here, so your `.ckpt` file and the wire format
  stay consistent. The terminal `file_index == file_count` / `"EOF"` state is
  already covered by the test suite.
- **Member 5** — `send_join_session()` accepts a `NULL` bitmap with
  `bmap_len = 0` for the first connect. `send_frame()` refuses anything over
  1 MB, so keep chunks at 64 KiB.
- **Member 6** — `opcode_name(hdr.type)` gives you a printable name for
  `[INFO]` / `[FAULT]` log lines.

## Things the layer guarantees

- Every integer on the wire is fixed-width big-endian — no struct is ever
  memcpy'd onto the socket, so there are no padding surprises between machines.
- Filenames may contain spaces or any byte; strings are length-prefixed, not
  delimiter-separated.
- A short `send()` or `recv()` is looped internally, so a 64 KB chunk always
  arrives whole or not at all.
- Parsers reject truncated payloads *and* payloads with trailing bytes, so a
  lying length field can never cause an over-read.

## Re-running the test yourself

```bash
cd _protocol_master
make test     # 154 assertions
make asan     # same tests under AddressSanitizer + UBSan
make clean
```
