/*
 * test_protocol.cpp - Member 2 standalone unit test
 *
 * Proves that protocol.cpp works WITHOUT any other member's code:
 *   - a local socketpair() replaces the real TCP connection
 *   - every opcode 0x01..0x0E is serialized into sv[0] and parsed from sv[1]
 *   - every field is asserted to come back bit-exact
 *   - malformed frames (bad magic / bad version / oversized length) are
 *     rejected with FRAME_PROTO_ERR
 *   - a clean close() is reported as FRAME_EOF
 *
 * Build:  g++ -O2 -Wall -Wextra -pthread -std=c++17 test_protocol.cpp protocol.cpp -o test_protocol
 * Run:    ./test_protocol
 */

#include "protocol.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string>
#include <vector>

static int g_pass = 0;
static int g_fail = 0;

static void check(bool cond, const char *what)
{
    if (cond) {
        g_pass++;
    } else {
        g_fail++;
        printf("  [FAIL] %s\n", what);
    }
}

static void banner(const char *name)
{
    printf("\n--- %s ---\n", name);
}

/* Make a predictable 16-byte session id so we can assert on it. */
static void make_session_id(uint8_t sid[16], uint8_t seed)
{
    for (int i = 0; i < 16; i++)
        sid[i] = static_cast<uint8_t>(seed + i);
}

/* Read one frame and assert the opcode is what we expected. */
static bool pull(int fd, uint8_t expect_op, FrameHeader *hdr,
                 std::vector<uint8_t> &payload)
{
    int rc = recv_frame(fd, hdr, payload);
    if (rc != FRAME_OK) {
        printf("  [FAIL] recv_frame returned %d while waiting for %s\n",
               rc, opcode_name(expect_op));
        g_fail++;
        return false;
    }
    if (hdr->type != expect_op) {
        printf("  [FAIL] expected opcode %s, got %s\n",
               opcode_name(expect_op), opcode_name(hdr->type));
        g_fail++;
        return false;
    }
    check(hdr->magic == PROTOCOL_MAGIC, "magic is 0x4954");
    check(hdr->version == PROTOCOL_VERSION, "version is 0x01");
    check(hdr->payload_length == payload.size(), "payload_length matches body");
    return true;
}

/* ================================================================== */
/* Test 1 : round trip of every opcode                                 */
/* ================================================================== */
static void test_all_opcodes(void)
{
    banner("Test 1: round-trip of all 14 opcodes");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("  [FAIL] socketpair() failed\n");
        g_fail++;
        return;
    }

    FrameHeader hdr;
    std::vector<uint8_t> payload;

    uint8_t sid[16];
    make_session_id(sid, 0xA0);

    /* ---- 0x01 GET ---- */
    check(send_get(sv[0], "Cane") == 0, "send GET");
    if (pull(sv[1], OP_GET, &hdr, payload)) {
        MsgGet m;
        check(parse_get(payload.data(), hdr.payload_length, &m), "parse GET");
        check(m.topic == "Cane", "GET.topic == Cane");
    }

    /* ---- 0x02 GET_OK ---- */
    check(send_get_ok(sv[0], sid, 1234u, 9876543210ULL) == 0, "send GET_OK");
    if (pull(sv[1], OP_GET_OK, &hdr, payload)) {
        MsgGetOk m;
        check(parse_get_ok(payload.data(), hdr.payload_length, &m), "parse GET_OK");
        check(memcmp(m.session_id, sid, 16) == 0, "GET_OK.session_id round trip");
        check(m.file_count == 1234u, "GET_OK.file_count");
        check(m.total_bytes == 9876543210ULL, "GET_OK.total_bytes (64-bit)");
    }

    /* ---- 0x03 ERROR ---- */
    check(send_error(sv[0], ERR_TOPIC_NOT_FOUND, "TOPIC_NOT_FOUND") == 0, "send ERROR");
    if (pull(sv[1], OP_ERROR, &hdr, payload)) {
        MsgError m;
        check(parse_error(payload.data(), hdr.payload_length, &m), "parse ERROR");
        check(m.code == 404, "ERROR.code == 404");
        check(m.reason == "TOPIC_NOT_FOUND", "ERROR.reason");
    }

    /* ---- 0x04 FILE_BEGIN (filename with a space, to prove no delimiters) ---- */
    check(send_file_begin(sv[0], 7u, 262144ULL, 1048576ULL, "my photo 01.jpeg") == 0,
          "send FILE_BEGIN");
    if (pull(sv[1], OP_FILE_BEGIN, &hdr, payload)) {
        MsgFileBegin m;
        check(parse_file_begin(payload.data(), hdr.payload_length, &m), "parse FILE_BEGIN");
        check(m.file_index == 7u, "FILE_BEGIN.file_index");
        check(m.byte_offset == 262144ULL, "FILE_BEGIN.byte_offset");
        check(m.bytes_following == 1048576ULL, "FILE_BEGIN.bytes_following");
        check(m.filename == "my photo 01.jpeg", "FILE_BEGIN.filename with space");
    }

    /* ---- 0x05 FILE_DATA : a full 64 KB chunk of binary bytes ---- */
    std::vector<uint8_t> chunk(CHUNK_SIZE);
    for (size_t i = 0; i < chunk.size(); i++)
        chunk[i] = static_cast<uint8_t>(i * 31 + 7);   /* includes 0x00 and 0xFF */

    check(send_file_data(sv[0], 7u, 131072ULL, chunk.data(),
                         static_cast<uint32_t>(chunk.size())) == 0, "send FILE_DATA 64KB");
    if (pull(sv[1], OP_FILE_DATA, &hdr, payload)) {
        MsgFileData m;
        check(parse_file_data(payload.data(), hdr.payload_length, &m), "parse FILE_DATA");
        check(m.file_index == 7u, "FILE_DATA.file_index");
        check(m.offset == 131072ULL, "FILE_DATA.offset");
        check(m.data.size() == chunk.size(), "FILE_DATA.data length");
        check(memcmp(m.data.data(), chunk.data(), chunk.size()) == 0,
              "FILE_DATA 64KB binary payload is bit-exact");
    }

    /* ---- 0x05 FILE_DATA : empty chunk edge case ---- */
    check(send_file_data(sv[0], 0u, 0ULL, NULL, 0u) == 0, "send FILE_DATA empty");
    if (pull(sv[1], OP_FILE_DATA, &hdr, payload)) {
        MsgFileData m;
        check(parse_file_data(payload.data(), hdr.payload_length, &m),
              "parse FILE_DATA empty");
        check(m.data.empty(), "FILE_DATA empty data");
    }

    /* ---- 0x06 FILE_END ---- */
    check(send_file_end(sv[0], 42u) == 0, "send FILE_END");
    if (pull(sv[1], OP_FILE_END, &hdr, payload)) {
        MsgFileEnd m;
        check(parse_file_end(payload.data(), hdr.payload_length, &m), "parse FILE_END");
        check(m.file_index == 42u, "FILE_END.file_index");
    }

    /* ---- 0x07 TRANSFER_END ---- */
    check(send_transfer_end(sv[0], 2623u, 150000000ULL) == 0, "send TRANSFER_END");
    if (pull(sv[1], OP_TRANSFER_END, &hdr, payload)) {
        MsgTransferEnd m;
        check(parse_transfer_end(payload.data(), hdr.payload_length, &m),
              "parse TRANSFER_END");
        check(m.files_sent == 2623u, "TRANSFER_END.files_sent");
        check(m.useful_bytes == 150000000ULL, "TRANSFER_END.useful_bytes");
    }

    /* ---- 0x08 CHECKPOINT_ACK ---- */
    check(send_checkpoint_ack(sv[0], sid, 3u, 196608ULL) == 0, "send CHECKPOINT_ACK");
    if (pull(sv[1], OP_CHECKPOINT_ACK, &hdr, payload)) {
        MsgCheckpointAck m;
        check(parse_checkpoint_ack(payload.data(), hdr.payload_length, &m),
              "parse CHECKPOINT_ACK");
        check(memcmp(m.session_id, sid, 16) == 0, "CHECKPOINT_ACK.session_id");
        check(m.file_index == 3u, "CHECKPOINT_ACK.file_index");
        check(m.ack_offset == 196608ULL, "CHECKPOINT_ACK.ack_offset");
    }

    /* ---- 0x09 RESUME ---- */
    check(send_resume(sv[0], sid, 5u, 262144ULL, "Cavallo", "OIP-xyz.jpeg") == 0,
          "send RESUME");
    if (pull(sv[1], OP_RESUME, &hdr, payload)) {
        MsgResume m;
        check(parse_resume(payload.data(), hdr.payload_length, &m), "parse RESUME");
        check(memcmp(m.session_id, sid, 16) == 0, "RESUME.session_id");
        check(m.file_index == 5u, "RESUME.file_index");
        check(m.byte_offset == 262144ULL, "RESUME.byte_offset");
        check(m.topic == "Cavallo", "RESUME.topic");
        check(m.filename == "OIP-xyz.jpeg", "RESUME.filename");
    }

    /* ---- 0x09 RESUME : terminal EOF state used by Member 4 ---- */
    check(send_resume(sv[0], sid, 2623u, 0ULL, "Cane", "EOF") == 0, "send RESUME EOF");
    if (pull(sv[1], OP_RESUME, &hdr, payload)) {
        MsgResume m;
        check(parse_resume(payload.data(), hdr.payload_length, &m), "parse RESUME EOF");
        check(m.file_index == 2623u && m.byte_offset == 0ULL && m.filename == "EOF",
              "RESUME terminal EOF state");
    }

    /* ---- 0x0A RESUME_OK ---- */
    check(send_resume_ok(sv[0], 5u, 262144ULL, 11u, 5000000ULL) == 0, "send RESUME_OK");
    if (pull(sv[1], OP_RESUME_OK, &hdr, payload)) {
        MsgResumeOk m;
        check(parse_resume_ok(payload.data(), hdr.payload_length, &m), "parse RESUME_OK");
        check(m.file_index == 5u, "RESUME_OK.file_index");
        check(m.accepted_offset == 262144ULL, "RESUME_OK.accepted_offset");
        check(m.rem_files == 11u, "RESUME_OK.rem_files");
        check(m.rem_bytes == 5000000ULL, "RESUME_OK.rem_bytes");
    }

    /* ---- 0x0B RESTART ---- */
    check(send_restart(sv[0], ERR_SESSION_EXPIRED, "SESSION_EXPIRED") == 0,
          "send RESTART");
    if (pull(sv[1], OP_RESTART, &hdr, payload)) {
        MsgError m;
        check(parse_restart(payload.data(), hdr.payload_length, &m), "parse RESTART");
        check(m.code == 410, "RESTART.code == 410");
        check(m.reason == "SESSION_EXPIRED", "RESTART.reason");
    }

    /* ---- 0x0C GET_ENHANCED ---- */
    check(send_get_enhanced(sv[0], 4u, "Elefante") == 0, "send GET_ENHANCED");
    if (pull(sv[1], OP_GET_ENHANCED, &hdr, payload)) {
        MsgGetEnhanced m;
        check(parse_get_enhanced(payload.data(), hdr.payload_length, &m),
              "parse GET_ENHANCED");
        check(m.num_streams == 4u, "GET_ENHANCED.num_streams");
        check(m.topic == "Elefante", "GET_ENHANCED.topic");
    }

    /* ---- 0x0D JOIN_SESSION with a chunk bitmap ---- */
    std::vector<uint8_t> bmap(300);
    for (size_t i = 0; i < bmap.size(); i++)
        bmap[i] = static_cast<uint8_t>(i % 251);

    check(send_join_session(sv[0], sid, 2u, bmap.data(),
                            static_cast<uint32_t>(bmap.size())) == 0,
          "send JOIN_SESSION");
    if (pull(sv[1], OP_JOIN_SESSION, &hdr, payload)) {
        MsgJoinSession m;
        check(parse_join_session(payload.data(), hdr.payload_length, &m),
              "parse JOIN_SESSION");
        check(memcmp(m.session_id, sid, 16) == 0, "JOIN_SESSION.session_id");
        check(m.conn_id == 2u, "JOIN_SESSION.conn_id");
        check(m.chunk_bitmap.size() == bmap.size(), "JOIN_SESSION.bmap_len");
        check(memcmp(m.chunk_bitmap.data(), bmap.data(), bmap.size()) == 0,
              "JOIN_SESSION.chunk_bitmap bit-exact");
    }

    /* ---- 0x0D JOIN_SESSION with an empty bitmap (first connect) ---- */
    check(send_join_session(sv[0], sid, 0u, NULL, 0u) == 0, "send JOIN_SESSION empty");
    if (pull(sv[1], OP_JOIN_SESSION, &hdr, payload)) {
        MsgJoinSession m;
        check(parse_join_session(payload.data(), hdr.payload_length, &m),
              "parse JOIN_SESSION empty");
        check(m.chunk_bitmap.empty(), "JOIN_SESSION empty bitmap");
    }

    /* ---- 0x0E ASSIGN_WORK ---- */
    check(send_assign_work(sv[0], 3u, 9u, 655360ULL, 65536u) == 0, "send ASSIGN_WORK");
    if (pull(sv[1], OP_ASSIGN_WORK, &hdr, payload)) {
        MsgAssignWork m;
        check(parse_assign_work(payload.data(), hdr.payload_length, &m),
              "parse ASSIGN_WORK");
        check(m.conn_id == 3u, "ASSIGN_WORK.conn_id");
        check(m.file_index == 9u, "ASSIGN_WORK.file_index");
        check(m.chunk_offset == 655360ULL, "ASSIGN_WORK.chunk_offset");
        check(m.chunk_len == 65536u, "ASSIGN_WORK.chunk_len");
    }

    close(sv[0]);
    close(sv[1]);
}

/* ================================================================== */
/* Test 2 : the wire header really is big-endian                       */
/* ================================================================== */
static void test_header_bytes_on_wire(void)
{
    banner("Test 2: raw header bytes are big-endian");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("  [FAIL] socketpair() failed\n");
        g_fail++;
        return;
    }

    uint8_t body[5] = { 1, 2, 3, 4, 5 };
    check(send_frame(sv[0], OP_FILE_END, body, 5) == 0, "send raw frame");

    uint8_t raw[13];
    check(recv_all(sv[1], raw, sizeof(raw)) == (ssize_t)sizeof(raw), "read 13 raw bytes");

    check(raw[0] == 0x49, "byte 0 == 0x49 ('I')");
    check(raw[1] == 0x54, "byte 1 == 0x54 ('T')");
    check(raw[2] == 0x01, "byte 2 == version 0x01");
    check(raw[3] == 0x06, "byte 3 == opcode FILE_END");
    check(raw[4] == 0x00 && raw[5] == 0x00 && raw[6] == 0x00 && raw[7] == 0x05,
          "bytes 4..7 == length 5, big-endian");
    check(raw[8] == 1 && raw[12] == 5, "payload follows header");

    close(sv[0]);
    close(sv[1]);
}

/* Helper: push a hand-made bad header and check recv_frame's verdict. */
static void bad_header_case(const uint8_t hdr[8], int expected_rc, const char *what)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("  [FAIL] socketpair() failed\n");
        g_fail++;
        return;
    }

    send_all(sv[0], hdr, 8);

    FrameHeader fh;
    std::vector<uint8_t> payload;
    int rc = recv_frame(sv[1], &fh, payload);
    check(rc == expected_rc, what);

    close(sv[0]);
    close(sv[1]);
}

/* ================================================================== */
/* Test 3 : malformed frames are rejected                              */
/* ================================================================== */
static void test_bad_frames(void)
{
    banner("Test 3: malformed frames rejected with FRAME_PROTO_ERR");

    /* wrong magic (0xDEAD instead of 0x4954) */
    {
        uint8_t h[8] = { 0xDE, 0xAD, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00 };
        bad_header_case(h, FRAME_PROTO_ERR, "bad magic -> FRAME_PROTO_ERR");
    }
    /* wrong version */
    {
        uint8_t h[8] = { 0x49, 0x54, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00 };
        bad_header_case(h, FRAME_PROTO_ERR, "bad version -> FRAME_PROTO_ERR");
    }
    /* payload_length = 2 MB, above the 1 MB cap */
    {
        uint8_t h[8] = { 0x49, 0x54, 0x01, 0x01, 0x00, 0x20, 0x00, 0x00 };
        bad_header_case(h, FRAME_PROTO_ERR, "oversized length -> FRAME_PROTO_ERR");
    }

    /* send_frame itself must refuse a payload above 1 MB */
    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
            std::vector<uint8_t> big(MAX_FRAME_PAYLOAD + 1, 0xAB);
            check(send_frame(sv[0], OP_FILE_DATA, big.data(),
                             static_cast<uint32_t>(big.size())) == -1,
                  "send_frame refuses payload > 1 MB");
            close(sv[0]);
            close(sv[1]);
        }
    }
}

/* ================================================================== */
/* Test 4 : clean EOF and mid-frame drop are distinguished             */
/* ================================================================== */
static void test_eof_and_drop(void)
{
    banner("Test 4: FRAME_EOF vs FRAME_SOCK_ERR");

    /* (a) peer closes with nothing pending -> clean EOF */
    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
            close(sv[0]);
            FrameHeader fh;
            std::vector<uint8_t> payload;
            check(recv_frame(sv[1], &fh, payload) == FRAME_EOF,
                  "clean close -> FRAME_EOF");
            close(sv[1]);
        }
    }

    /* (b) peer sends a valid header, then dies before the body arrives.
     *     This is exactly what the fault injector does mid-chunk. */
    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
            uint8_t h[8];
            uint16_t magic_be = htons(PROTOCOL_MAGIC);
            uint32_t len_be   = htonl(100u);
            memcpy(h + 0, &magic_be, 2);
            h[2] = PROTOCOL_VERSION;
            h[3] = OP_FILE_DATA;
            memcpy(h + 4, &len_be, 4);

            send_all(sv[0], h, 8);
            send_all(sv[0], h, 8);          /* only 8 of the 100 promised bytes */
            close(sv[0]);

            FrameHeader fh;
            std::vector<uint8_t> payload;
            check(recv_frame(sv[1], &fh, payload) == FRAME_SOCK_ERR,
                  "truncated body -> FRAME_SOCK_ERR");
            close(sv[1]);
        }
    }
}

/* ================================================================== */
/* Test 5 : truncated / over-long payloads are rejected by parsers     */
/* ================================================================== */
static void test_parser_guards(void)
{
    banner("Test 5: parsers reject malformed payloads");

    /* GET claims a 10-byte topic but only 2 bytes follow */
    {
        uint8_t p[4] = { 0x00, 0x0A, 'C', 'a' };
        MsgGet m;
        check(parse_get(p, 4, &m) == false, "truncated GET rejected");
    }
    /* GET with trailing garbage must also fail (strict full-consume rule) */
    {
        uint8_t p[7] = { 0x00, 0x04, 'C', 'a', 'n', 'e', 0xFF };
        MsgGet m;
        check(parse_get(p, 7, &m) == false, "GET with trailing byte rejected");
    }
    /* FILE_END needs exactly 4 bytes */
    {
        uint8_t p[3] = { 0x00, 0x00, 0x00 };
        MsgFileEnd m;
        check(parse_file_end(p, 3, &m) == false, "short FILE_END rejected");
    }
    /* empty payload where fields are required */
    {
        MsgGetOk m;
        check(parse_get_ok(NULL, 0, &m) == false, "empty GET_OK rejected");
    }
    /* FILE_DATA claiming more data than present */
    {
        std::vector<uint8_t> p;
        uint8_t hdr[16];
        memset(hdr, 0, sizeof(hdr));
        hdr[15] = 0xFF;                      /* data_len = 255, but 0 bytes follow */
        p.assign(hdr, hdr + 16);
        MsgFileData m;
        check(parse_file_data(p.data(), 16, &m) == false,
              "FILE_DATA with lying data_len rejected");
    }
}

/* ================================================================== */
/* Test 6 : session id helpers                                         */
/* ================================================================== */
static void test_session_id_helpers(void)
{
    banner("Test 6: session id zero / hex helpers");

    uint8_t sid[16];
    zero_session_id(sid);
    bool all_zero = true;
    for (int i = 0; i < 16; i++)
        if (sid[i] != 0)
            all_zero = false;
    check(all_zero, "zero_session_id() gives 16 zero bytes (Part I / Case 1)");

    uint8_t original[16];
    make_session_id(original, 0x10);

    char hex[33];
    session_id_to_hex(original, hex);
    check(strlen(hex) == 32, "hex string is 32 chars");
    check(strcmp(hex, "101112131415161718191a1b1c1d1e1f") == 0, "hex value correct");

    uint8_t back[16];
    check(hex_to_session_id(hex, back), "hex parses back");
    check(memcmp(back, original, 16) == 0, "hex round trip is exact");
    check(hex_to_session_id("zzzz", back) == false, "malformed hex rejected");
}

int main(void)
{
    printf("=========================================\n");
    printf(" IT305 protocol.cpp unit tests (Member 2)\n");
    printf("=========================================\n");

    test_all_opcodes();
    test_header_bytes_on_wire();
    test_bad_frames();
    test_eof_and_drop();
    test_parser_guards();
    test_session_id_helpers();

    printf("\n=========================================\n");
    printf(" PASSED: %d   FAILED: %d\n", g_pass, g_fail);
    printf("=========================================\n");

    return (g_fail == 0) ? 0 : 1;
}
