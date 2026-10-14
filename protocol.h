#ifndef PROTOCOL_H
#define PROTOCOL_H

/*
 * protocol.h - Member 2
 * Wire framing layer for the Fault-Tolerant Topic-Based File Distribution Service.
 *
 * This module is the ONLY place in the project that touches raw bytes on the
 * socket. Everyone else (server loops, fault injector, session manager,
 * enhanced parallel client) calls the functions below instead of calling
 * send()/recv() directly.
 *
 * Three layers live here:
 *   Layer 1 : send_all() / recv_all()      - loop until exactly N bytes moved
 *   Layer 2 : send_frame() / recv_frame()  - 8-byte big-endian length-prefixed header
 *   Layer 3 : serialize_* / parse_*        - exact payload layouts for opcodes 0x01-0x0E
 *
 * Wire rules (Design Doc Section 2.2):
 *   - every integer is fixed width and BIG-ENDIAN (network byte order)
 *   - no C structs are ever memcpy'd onto the wire (compiler padding is unsafe)
 *   - every variable-length string is [uint16_t length][raw bytes], NO null terminator
 *   - session_id is always 16 raw bytes on the wire (all zeros in Part I / Case 1)
 */

#include "common_types.h"

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <string>
#include <vector>

/* ------------------------------------------------------------------ */
/* Return codes for recv_frame()                                       */
/* ------------------------------------------------------------------ */
#define FRAME_OK          1    /* a complete, valid frame was received      */
#define FRAME_EOF         0    /* peer closed the socket cleanly (no frame) */
#define FRAME_SOCK_ERR   (-1)  /* socket error / connection reset           */
#define FRAME_PROTO_ERR  (-2)  /* bad magic, bad version, or payload too big*/

/* ------------------------------------------------------------------ */
/* Error codes carried inside ERROR (0x03) and RESTART (0x0B)          */
/* ------------------------------------------------------------------ */
#define ERR_BAD_REQUEST        400
#define ERR_TOPIC_NOT_FOUND    404
#define ERR_IO_ERROR           500
#define ERR_TOPIC_MISMATCH     409   /* also used for FILENAME_MISMATCH */
#define ERR_FILENAME_MISMATCH  409
#define ERR_SESSION_EXPIRED    410
#define ERR_INVALID_OFFSET     416   /* also used for HIGHWATER_EXCEEDED */

/* Size of the fixed frame header, in bytes. */
#define FRAME_HEADER_SIZE 8

/* ================================================================== */
/* LAYER 1 - loop-complete socket helpers                              */
/* ================================================================== */

/*
 * Send exactly len bytes. A single send() may move fewer bytes than asked,
 * so we loop. MSG_NOSIGNAL is used so a dead peer gives us EPIPE instead of
 * killing the whole process with SIGPIPE.
 *
 * Returns: len on success, -1 on socket error.
 */
ssize_t send_all(int sockfd, const void *buf, size_t len);

/*
 * Receive exactly len bytes.
 *
 * Returns: len on success,
 *          0  if the peer closed the connection cleanly before any byte of
 *             this request arrived (clean EOF),
 *          -1 on socket error (ECONNRESET etc.) or on a short read caused by
 *             the peer dying halfway through.
 */
ssize_t recv_all(int sockfd, void *buf, size_t len);

/* ================================================================== */
/* LAYER 2 - 8-byte length-prefixed framing                            */
/* ================================================================== */

/*
 * Frame layout on the wire (big-endian):
 *   byte 0..1 : magic          = 0x4954 ("IT")
 *   byte 2    : version        = 0x01
 *   byte 3    : opcode         = 0x01 .. 0x0E
 *   byte 4..7 : payload_length (uint32_t)
 *   byte 8..  : payload, exactly payload_length bytes
 *
 * payload may be NULL when payload_len == 0.
 * Returns 0 on success, -1 on failure.
 */
int send_frame(int sockfd, uint8_t opcode, const uint8_t *payload, uint32_t payload_len);

/* Convenience wrapper: build the frame straight from a serialized vector. */
int send_frame_vec(int sockfd, uint8_t opcode, const std::vector<uint8_t> &payload);

/*
 * Read one full frame. out_payload is resized to the exact payload length.
 * Returns FRAME_OK / FRAME_EOF / FRAME_SOCK_ERR / FRAME_PROTO_ERR.
 */
int recv_frame(int sockfd, FrameHeader *out_hdr, std::vector<uint8_t> &out_payload);

/* Human readable opcode name, for [INFO]/[FAULT] logging. Never returns NULL. */
const char *opcode_name(uint8_t opcode);

/* ================================================================== */
/* LAYER 3 - message structs (parser output)                           */
/* ================================================================== */

struct MsgGet {                       /* 0x01 */
    std::string topic;
};

struct MsgGetOk {                     /* 0x02 */
    uint8_t  session_id[16];
    uint32_t file_count;
    uint64_t total_bytes;
};

struct MsgError {                     /* 0x03 and 0x0B (identical layout) */
    uint16_t    code;
    std::string reason;
};

struct MsgFileBegin {                 /* 0x04 */
    uint32_t    file_index;
    uint64_t    byte_offset;
    uint64_t    bytes_following;
    std::string filename;
};

struct MsgFileData {                  /* 0x05 */
    uint32_t             file_index;
    uint64_t             offset;
    std::vector<uint8_t> data;
};

struct MsgFileEnd {                   /* 0x06 */
    uint32_t file_index;
};

struct MsgTransferEnd {               /* 0x07 */
    uint32_t files_sent;
    uint64_t useful_bytes;
};

struct MsgCheckpointAck {             /* 0x08 */
    uint8_t  session_id[16];
    uint32_t file_index;
    uint64_t ack_offset;
};

struct MsgResume {                    /* 0x09 */
    uint8_t     session_id[16];
    uint32_t    file_index;
    uint64_t    byte_offset;
    std::string topic;
    std::string filename;
};

struct MsgResumeOk {                  /* 0x0A */
    uint32_t file_index;
    uint64_t accepted_offset;
    uint32_t rem_files;
    uint64_t rem_bytes;
};

struct MsgGetEnhanced {               /* 0x0C */
    uint16_t    num_streams;
    std::string topic;
};

struct MsgJoinSession {               /* 0x0D */
    uint8_t              session_id[16];
    uint32_t             conn_id;
    std::vector<uint8_t> chunk_bitmap;
};

struct MsgAssignWork {                /* 0x0E */
    uint32_t conn_id;
    uint32_t file_index;
    uint64_t chunk_offset;
    uint32_t chunk_len;
};

/* ================================================================== */
/* LAYER 3 - serializers (build payload)                               */
/* ================================================================== */
/* Each one CLEARS out and refills it with the exact bytes of Table 2. */

void serialize_get(const std::string &topic, std::vector<uint8_t> &out);

void serialize_get_ok(const uint8_t session_id[16], uint32_t file_count,
                      uint64_t total_bytes, std::vector<uint8_t> &out);

void serialize_error(uint16_t code, const std::string &reason,
                     std::vector<uint8_t> &out);

void serialize_file_begin(uint32_t file_index, uint64_t byte_offset,
                          uint64_t bytes_following, const std::string &filename,
                          std::vector<uint8_t> &out);

void serialize_file_data(uint32_t file_index, uint64_t offset,
                         const uint8_t *data, uint32_t data_len,
                         std::vector<uint8_t> &out);

void serialize_file_end(uint32_t file_index, std::vector<uint8_t> &out);

void serialize_transfer_end(uint32_t files_sent, uint64_t useful_bytes,
                            std::vector<uint8_t> &out);

void serialize_checkpoint_ack(const uint8_t session_id[16], uint32_t file_index,
                              uint64_t ack_offset, std::vector<uint8_t> &out);

void serialize_resume(const uint8_t session_id[16], uint32_t file_index,
                      uint64_t byte_offset, const std::string &topic,
                      const std::string &filename, std::vector<uint8_t> &out);

void serialize_resume_ok(uint32_t file_index, uint64_t accepted_offset,
                         uint32_t rem_files, uint64_t rem_bytes,
                         std::vector<uint8_t> &out);

void serialize_get_enhanced(uint16_t num_streams, const std::string &topic,
                            std::vector<uint8_t> &out);

void serialize_join_session(const uint8_t session_id[16], uint32_t conn_id,
                            const uint8_t *chunk_bitmap, uint32_t bmap_len,
                            std::vector<uint8_t> &out);

void serialize_assign_work(uint32_t conn_id, uint32_t file_index,
                           uint64_t chunk_offset, uint32_t chunk_len,
                           std::vector<uint8_t> &out);

/* RESTART (0x0B) uses exactly the same layout as ERROR (0x03). */
void serialize_restart(uint16_t code, const std::string &reason,
                       std::vector<uint8_t> &out);

/* ================================================================== */
/* LAYER 3 - parsers (read payload)                                    */
/* ================================================================== */
/*
 * Every parser returns true only if the payload decoded cleanly AND every
 * single byte was consumed. A malformed or truncated payload returns false,
 * and the caller must treat that as a PROTOCOL_ERROR.
 */

bool parse_get(const uint8_t *payload, uint32_t len, MsgGet *out);
bool parse_get_ok(const uint8_t *payload, uint32_t len, MsgGetOk *out);
bool parse_error(const uint8_t *payload, uint32_t len, MsgError *out);
bool parse_restart(const uint8_t *payload, uint32_t len, MsgError *out);
bool parse_file_begin(const uint8_t *payload, uint32_t len, MsgFileBegin *out);
bool parse_file_data(const uint8_t *payload, uint32_t len, MsgFileData *out);
bool parse_file_end(const uint8_t *payload, uint32_t len, MsgFileEnd *out);
bool parse_transfer_end(const uint8_t *payload, uint32_t len, MsgTransferEnd *out);
bool parse_checkpoint_ack(const uint8_t *payload, uint32_t len, MsgCheckpointAck *out);
bool parse_resume(const uint8_t *payload, uint32_t len, MsgResume *out);
bool parse_resume_ok(const uint8_t *payload, uint32_t len, MsgResumeOk *out);
bool parse_get_enhanced(const uint8_t *payload, uint32_t len, MsgGetEnhanced *out);
bool parse_join_session(const uint8_t *payload, uint32_t len, MsgJoinSession *out);
bool parse_assign_work(const uint8_t *payload, uint32_t len, MsgAssignWork *out);

/* ================================================================== */
/* SEND HELPERS - serialize + send_frame in one call                   */
/* ================================================================== */
/* These are what the rest of the team should normally call.           */
/* All of them return 0 on success and -1 on socket failure.           */

int send_get(int fd, const std::string &topic);
int send_get_ok(int fd, const uint8_t session_id[16], uint32_t file_count,
                uint64_t total_bytes);
int send_error(int fd, uint16_t code, const std::string &reason);
int send_file_begin(int fd, uint32_t file_index, uint64_t byte_offset,
                    uint64_t bytes_following, const std::string &filename);
int send_file_data(int fd, uint32_t file_index, uint64_t offset,
                   const uint8_t *data, uint32_t data_len);
int send_file_end(int fd, uint32_t file_index);
int send_transfer_end(int fd, uint32_t files_sent, uint64_t useful_bytes);
int send_checkpoint_ack(int fd, const uint8_t session_id[16], uint32_t file_index,
                        uint64_t ack_offset);
int send_resume(int fd, const uint8_t session_id[16], uint32_t file_index,
                uint64_t byte_offset, const std::string &topic,
                const std::string &filename);
int send_resume_ok(int fd, uint32_t file_index, uint64_t accepted_offset,
                   uint32_t rem_files, uint64_t rem_bytes);
int send_restart(int fd, uint16_t code, const std::string &reason);
int send_get_enhanced(int fd, uint16_t num_streams, const std::string &topic);
int send_join_session(int fd, const uint8_t session_id[16], uint32_t conn_id,
                      const uint8_t *chunk_bitmap, uint32_t bmap_len);
int send_assign_work(int fd, uint32_t conn_id, uint32_t file_index,
                     uint64_t chunk_offset, uint32_t chunk_len);

/* ------------------------------------------------------------------ */
/* Small helper used by Part I and Case 1, where session_id is all 0.  */
/* ------------------------------------------------------------------ */
void zero_session_id(uint8_t session_id[16]);

/* Render a 16-byte session id as a 32-char lowercase hex string.
 * out_hex must have room for 33 bytes (32 chars + '\0'). Used only for
 * checkpoint files and log lines, never on the wire. */
void session_id_to_hex(const uint8_t session_id[16], char out_hex[33]);

/* Inverse of session_id_to_hex(). Returns false if hex is malformed. */
bool hex_to_session_id(const char *hex, uint8_t out_session_id[16]);

#endif /* PROTOCOL_H */
