/*
 * protocol.cpp - Member 2
 * Implementation of the length-prefixed binary wire framing layer.
 *
 * Build: g++ -O2 -Wall -Wextra -pthread -std=c++17 -c protocol.cpp
 */

#include "protocol.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>   /* htons, htonl, ntohs, ntohl */
#include <endian.h>      /* htobe64, be64toh           */

/* Some systems do not define MSG_NOSIGNAL (e.g. macOS). Fall back to 0 there
 * so the file still compiles; on Linux lab machines the real flag is used. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* ================================================================== */
/* LAYER 1 - loop-complete socket helpers                              */
/* ================================================================== */

ssize_t send_all(int sockfd, const void *buf, size_t len)
{
    const uint8_t *ptr = static_cast<const uint8_t *>(buf);
    size_t total = 0;

    while (total < len) {
        ssize_t n = send(sockfd, ptr + total, len - total, MSG_NOSIGNAL);

        if (n < 0) {
            if (errno == EINTR)
                continue;          /* interrupted by a signal, just retry */
            return -1;             /* EPIPE / ECONNRESET / real error     */
        }
        if (n == 0)
            return -1;             /* should not happen for send()        */

        total += static_cast<size_t>(n);
    }
    return static_cast<ssize_t>(len);
}

ssize_t recv_all(int sockfd, void *buf, size_t len)
{
    uint8_t *ptr = static_cast<uint8_t *>(buf);
    size_t total = 0;

    while (total < len) {
        ssize_t n = recv(sockfd, ptr + total, len - total, 0);

        if (n < 0) {
            if (errno == EINTR)
                continue;          /* interrupted by a signal, just retry */
            return -1;             /* ECONNRESET / real error             */
        }
        if (n == 0) {
            /* Peer closed the connection.
             * If we had not read a single byte yet this is a clean EOF.
             * If we were halfway through a frame the peer died mid-message,
             * which is a broken connection, not a clean shutdown. */
            if (total == 0)
                return 0;
            return -1;
        }

        total += static_cast<size_t>(n);
    }
    return static_cast<ssize_t>(len);
}

/* ================================================================== */
/* LAYER 2 - 8-byte length-prefixed framing                            */
/* ================================================================== */

int send_frame(int sockfd, uint8_t opcode, const uint8_t *payload, uint32_t payload_len)
{
    if (payload_len > MAX_FRAME_PAYLOAD)
        return -1;                             /* refuse to build a bad frame */
    if (payload_len > 0 && payload == NULL)
        return -1;

    uint8_t hdr[FRAME_HEADER_SIZE];

    uint16_t magic_be = htons(PROTOCOL_MAGIC);
    uint32_t len_be   = htonl(payload_len);

    memcpy(hdr + 0, &magic_be, 2);             /* bytes 0..1 : magic   */
    hdr[2] = PROTOCOL_VERSION;                 /* byte  2    : version */
    hdr[3] = opcode;                           /* byte  3    : opcode  */
    memcpy(hdr + 4, &len_be, 4);               /* bytes 4..7 : length  */

    if (send_all(sockfd, hdr, FRAME_HEADER_SIZE) != (ssize_t)FRAME_HEADER_SIZE)
        return -1;

    if (payload_len > 0) {
        if (send_all(sockfd, payload, payload_len) != (ssize_t)payload_len)
            return -1;
    }
    return 0;
}

int send_frame_vec(int sockfd, uint8_t opcode, const std::vector<uint8_t> &payload)
{
    const uint8_t *p = payload.empty() ? NULL : payload.data();
    return send_frame(sockfd, opcode, p, static_cast<uint32_t>(payload.size()));
}

int recv_frame(int sockfd, FrameHeader *out_hdr, std::vector<uint8_t> &out_payload)
{
    if (out_hdr == NULL)
        return FRAME_PROTO_ERR;

    uint8_t raw_hdr[FRAME_HEADER_SIZE];

    ssize_t r = recv_all(sockfd, raw_hdr, FRAME_HEADER_SIZE);
    if (r == 0)
        return FRAME_EOF;                      /* clean shutdown by peer */
    if (r < 0)
        return FRAME_SOCK_ERR;                 /* dropped mid-stream     */

    uint16_t magic_be;
    uint32_t len_be;
    memcpy(&magic_be, raw_hdr + 0, 2);
    memcpy(&len_be,   raw_hdr + 4, 4);

    out_hdr->magic          = ntohs(magic_be);
    out_hdr->version        = raw_hdr[2];
    out_hdr->type           = raw_hdr[3];
    out_hdr->payload_length = ntohl(len_be);

    /* Frame sanity checks (Design Doc Section 2.2, rule 4). */
    if (out_hdr->magic != PROTOCOL_MAGIC)
        return FRAME_PROTO_ERR;
    if (out_hdr->version != PROTOCOL_VERSION)
        return FRAME_PROTO_ERR;
    if (out_hdr->payload_length > MAX_FRAME_PAYLOAD)
        return FRAME_PROTO_ERR;

    out_payload.clear();
    if (out_hdr->payload_length > 0) {
        out_payload.resize(out_hdr->payload_length);
        ssize_t p = recv_all(sockfd, out_payload.data(), out_hdr->payload_length);
        if (p <= 0)
            return FRAME_SOCK_ERR;             /* header arrived, body did not */
    }
    return FRAME_OK;
}

const char *opcode_name(uint8_t opcode)
{
    switch (opcode) {
    case OP_GET:            return "GET";
    case OP_GET_OK:         return "GET_OK";
    case OP_ERROR:          return "ERROR";
    case OP_FILE_BEGIN:     return "FILE_BEGIN";
    case OP_FILE_DATA:      return "FILE_DATA";
    case OP_FILE_END:       return "FILE_END";
    case OP_TRANSFER_END:   return "TRANSFER_END";
    case OP_CHECKPOINT_ACK: return "CHECKPOINT_ACK";
    case OP_RESUME:         return "RESUME";
    case OP_RESUME_OK:      return "RESUME_OK";
    case OP_RESTART:        return "RESTART";
    case OP_GET_ENHANCED:   return "GET_ENHANCED";
    case OP_JOIN_SESSION:   return "JOIN_SESSION";
    case OP_ASSIGN_WORK:    return "ASSIGN_WORK";
    default:                return "UNKNOWN";
    }
}

/* ================================================================== */
/* Internal byte writers (big-endian, no struct padding ever)          */
/* ================================================================== */

static void put_u16(std::vector<uint8_t> &b, uint16_t v)
{
    uint16_t n = htons(v);
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&n);
    b.push_back(p[0]);
    b.push_back(p[1]);
}

static void put_u32(std::vector<uint8_t> &b, uint32_t v)
{
    uint32_t n = htonl(v);
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&n);
    b.insert(b.end(), p, p + 4);
}

static void put_u64(std::vector<uint8_t> &b, uint64_t v)
{
    uint64_t n = htobe64(v);
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&n);
    b.insert(b.end(), p, p + 8);
}

static void put_bytes(std::vector<uint8_t> &b, const uint8_t *src, size_t n)
{
    if (n > 0 && src != NULL)
        b.insert(b.end(), src, src + n);
}

/* [uint16_t length][raw bytes] - no null terminator on the wire. */
static void put_string(std::vector<uint8_t> &b, const std::string &s)
{
    size_t n = s.size();
    if (n > 65535)
        n = 65535;                             /* defensive clamp */
    put_u16(b, static_cast<uint16_t>(n));
    b.insert(b.end(), s.begin(), s.begin() + static_cast<long>(n));
}

/* ================================================================== */
/* Internal byte reader                                                */
/* ================================================================== */

struct Reader {
    const uint8_t *buf;
    uint32_t       len;
    uint32_t       pos;
    bool           ok;
};

static void rd_init(Reader &r, const uint8_t *buf, uint32_t len)
{
    r.buf = buf;
    r.len = len;
    r.pos = 0;
    r.ok  = true;
}

static bool rd_have(Reader &r, uint32_t n)
{
    if (!r.ok)
        return false;
    if (r.len - r.pos < n) {                   /* no overflow: pos <= len always */
        r.ok = false;
        return false;
    }
    return true;
}

static void rd_u16(Reader &r, uint16_t *out)
{
    if (!rd_have(r, 2))
        return;
    uint16_t n;
    memcpy(&n, r.buf + r.pos, 2);
    *out = ntohs(n);
    r.pos += 2;
}

static void rd_u32(Reader &r, uint32_t *out)
{
    if (!rd_have(r, 4))
        return;
    uint32_t n;
    memcpy(&n, r.buf + r.pos, 4);
    *out = ntohl(n);
    r.pos += 4;
}

static void rd_u64(Reader &r, uint64_t *out)
{
    if (!rd_have(r, 8))
        return;
    uint64_t n;
    memcpy(&n, r.buf + r.pos, 8);
    *out = be64toh(n);
    r.pos += 8;
}

static void rd_bytes(Reader &r, uint8_t *dst, uint32_t n)
{
    if (!rd_have(r, n))
        return;
    memcpy(dst, r.buf + r.pos, n);
    r.pos += n;
}

static void rd_vector(Reader &r, std::vector<uint8_t> *dst, uint32_t n)
{
    if (!rd_have(r, n))
        return;
    dst->assign(r.buf + r.pos, r.buf + r.pos + n);
    r.pos += n;
}

static void rd_string(Reader &r, std::string *out)
{
    uint16_t slen = 0;
    rd_u16(r, &slen);
    if (!rd_have(r, slen))
        return;
    out->assign(reinterpret_cast<const char *>(r.buf + r.pos), slen);
    r.pos += slen;
}

/* A payload is valid only if it decoded cleanly AND was fully consumed. */
static bool rd_done(const Reader &r)
{
    return r.ok && r.pos == r.len;
}

/* ================================================================== */
/* LAYER 3 - serializers (exact layouts from Table 2)                  */
/* ================================================================== */

/* 0x01 GET : [topic_len:u16][topic] */
void serialize_get(const std::string &topic, std::vector<uint8_t> &out)
{
    out.clear();
    put_string(out, topic);
}

/* 0x02 GET_OK : [session_id:16][file_count:u32][total_bytes:u64] */
void serialize_get_ok(const uint8_t session_id[16], uint32_t file_count,
                      uint64_t total_bytes, std::vector<uint8_t> &out)
{
    out.clear();
    put_bytes(out, session_id, 16);
    put_u32(out, file_count);
    put_u64(out, total_bytes);
}

/* 0x03 ERROR : [err_code:u16][msg_len:u16][reason] */
void serialize_error(uint16_t code, const std::string &reason,
                     std::vector<uint8_t> &out)
{
    out.clear();
    put_u16(out, code);
    put_string(out, reason);
}

/* 0x0B RESTART : identical layout to ERROR */
void serialize_restart(uint16_t code, const std::string &reason,
                       std::vector<uint8_t> &out)
{
    serialize_error(code, reason, out);
}

/* 0x04 FILE_BEGIN :
 * [file_index:u32][byte_offset:u64][bytes_following:u64][name_len:u16][filename] */
void serialize_file_begin(uint32_t file_index, uint64_t byte_offset,
                          uint64_t bytes_following, const std::string &filename,
                          std::vector<uint8_t> &out)
{
    out.clear();
    put_u32(out, file_index);
    put_u64(out, byte_offset);
    put_u64(out, bytes_following);
    put_string(out, filename);
}

/* 0x05 FILE_DATA : [file_index:u32][offset:u64][data_len:u32][data] */
void serialize_file_data(uint32_t file_index, uint64_t offset,
                         const uint8_t *data, uint32_t data_len,
                         std::vector<uint8_t> &out)
{
    out.clear();
    out.reserve(16 + data_len);
    put_u32(out, file_index);
    put_u64(out, offset);
    put_u32(out, data_len);
    put_bytes(out, data, data_len);
}

/* 0x06 FILE_END : [file_index:u32] */
void serialize_file_end(uint32_t file_index, std::vector<uint8_t> &out)
{
    out.clear();
    put_u32(out, file_index);
}

/* 0x07 TRANSFER_END : [files_sent:u32][useful_bytes:u64] */
void serialize_transfer_end(uint32_t files_sent, uint64_t useful_bytes,
                            std::vector<uint8_t> &out)
{
    out.clear();
    put_u32(out, files_sent);
    put_u64(out, useful_bytes);
}

/* 0x08 CHECKPOINT_ACK : [session_id:16][file_index:u32][ack_offset:u64] */
void serialize_checkpoint_ack(const uint8_t session_id[16], uint32_t file_index,
                              uint64_t ack_offset, std::vector<uint8_t> &out)
{
    out.clear();
    put_bytes(out, session_id, 16);
    put_u32(out, file_index);
    put_u64(out, ack_offset);
}

/* 0x09 RESUME :
 * [session_id:16][file_index:u32][byte_offset:u64]
 * [topic_len:u16][topic][name_len:u16][filename] */
void serialize_resume(const uint8_t session_id[16], uint32_t file_index,
                      uint64_t byte_offset, const std::string &topic,
                      const std::string &filename, std::vector<uint8_t> &out)
{
    out.clear();
    put_bytes(out, session_id, 16);
    put_u32(out, file_index);
    put_u64(out, byte_offset);
    put_string(out, topic);
    put_string(out, filename);
}

/* 0x0A RESUME_OK :
 * [file_index:u32][accepted_offset:u64][rem_files:u32][rem_bytes:u64] */
void serialize_resume_ok(uint32_t file_index, uint64_t accepted_offset,
                         uint32_t rem_files, uint64_t rem_bytes,
                         std::vector<uint8_t> &out)
{
    out.clear();
    put_u32(out, file_index);
    put_u64(out, accepted_offset);
    put_u32(out, rem_files);
    put_u64(out, rem_bytes);
}

/* 0x0C GET_ENHANCED : [num_streams:u16][topic_len:u16][topic] */
void serialize_get_enhanced(uint16_t num_streams, const std::string &topic,
                            std::vector<uint8_t> &out)
{
    out.clear();
    put_u16(out, num_streams);
    put_string(out, topic);
}

/* 0x0D JOIN_SESSION :
 * [session_id:16][conn_id:u32][bmap_len:u32][chunk_bitmap] */
void serialize_join_session(const uint8_t session_id[16], uint32_t conn_id,
                            const uint8_t *chunk_bitmap, uint32_t bmap_len,
                            std::vector<uint8_t> &out)
{
    out.clear();
    put_bytes(out, session_id, 16);
    put_u32(out, conn_id);
    put_u32(out, bmap_len);
    put_bytes(out, chunk_bitmap, bmap_len);
}

/* 0x0E ASSIGN_WORK :
 * [conn_id:u32][file_index:u32][chunk_offset:u64][chunk_len:u32] */
void serialize_assign_work(uint32_t conn_id, uint32_t file_index,
                           uint64_t chunk_offset, uint32_t chunk_len,
                           std::vector<uint8_t> &out)
{
    out.clear();
    put_u32(out, conn_id);
    put_u32(out, file_index);
    put_u64(out, chunk_offset);
    put_u32(out, chunk_len);
}

/* ================================================================== */
/* LAYER 3 - parsers                                                   */
/* ================================================================== */

bool parse_get(const uint8_t *payload, uint32_t len, MsgGet *out)
{
    if (out == NULL) return false;
    Reader r;
    rd_init(r, payload, len);
    rd_string(r, &out->topic);
    return rd_done(r);
}

bool parse_get_ok(const uint8_t *payload, uint32_t len, MsgGetOk *out)
{
    if (out == NULL) return false;
    Reader r;
    rd_init(r, payload, len);
    rd_bytes(r, out->session_id, 16);
    rd_u32(r, &out->file_count);
    rd_u64(r, &out->total_bytes);
    return rd_done(r);
}

bool parse_error(const uint8_t *payload, uint32_t len, MsgError *out)
{
    if (out == NULL) return false;
    Reader r;
    rd_init(r, payload, len);
    rd_u16(r, &out->code);
    rd_string(r, &out->reason);
    return rd_done(r);
}

bool parse_restart(const uint8_t *payload, uint32_t len, MsgError *out)
{
    return parse_error(payload, len, out);
}

bool parse_file_begin(const uint8_t *payload, uint32_t len, MsgFileBegin *out)
{
    if (out == NULL) return false;
    Reader r;
    rd_init(r, payload, len);
    rd_u32(r, &out->file_index);
    rd_u64(r, &out->byte_offset);
    rd_u64(r, &out->bytes_following);
    rd_string(r, &out->filename);
    return rd_done(r);
}

bool parse_file_data(const uint8_t *payload, uint32_t len, MsgFileData *out)
{
    if (out == NULL) return false;
    Reader r;
    rd_init(r, payload, len);
    rd_u32(r, &out->file_index);
    rd_u64(r, &out->offset);

    uint32_t data_len = 0;
    rd_u32(r, &data_len);
    if (!r.ok)
        return false;

    out->data.clear();
    rd_vector(r, &out->data, data_len);
    return rd_done(r);
}

bool parse_file_end(const uint8_t *payload, uint32_t len, MsgFileEnd *out)
{
    if (out == NULL) return false;
    Reader r;
    rd_init(r, payload, len);
    rd_u32(r, &out->file_index);
    return rd_done(r);
}

bool parse_transfer_end(const uint8_t *payload, uint32_t len, MsgTransferEnd *out)
{
    if (out == NULL) return false;
    Reader r;
    rd_init(r, payload, len);
    rd_u32(r, &out->files_sent);
    rd_u64(r, &out->useful_bytes);
    return rd_done(r);
}

bool parse_checkpoint_ack(const uint8_t *payload, uint32_t len, MsgCheckpointAck *out)
{
    if (out == NULL) return false;
    Reader r;
    rd_init(r, payload, len);
    rd_bytes(r, out->session_id, 16);
    rd_u32(r, &out->file_index);
    rd_u64(r, &out->ack_offset);
    return rd_done(r);
}

bool parse_resume(const uint8_t *payload, uint32_t len, MsgResume *out)
{
    if (out == NULL) return false;
    Reader r;
    rd_init(r, payload, len);
    rd_bytes(r, out->session_id, 16);
    rd_u32(r, &out->file_index);
    rd_u64(r, &out->byte_offset);
    rd_string(r, &out->topic);
    rd_string(r, &out->filename);
    return rd_done(r);
}

bool parse_resume_ok(const uint8_t *payload, uint32_t len, MsgResumeOk *out)
{
    if (out == NULL) return false;
    Reader r;
    rd_init(r, payload, len);
    rd_u32(r, &out->file_index);
    rd_u64(r, &out->accepted_offset);
    rd_u32(r, &out->rem_files);
    rd_u64(r, &out->rem_bytes);
    return rd_done(r);
}

bool parse_get_enhanced(const uint8_t *payload, uint32_t len, MsgGetEnhanced *out)
{
    if (out == NULL) return false;
    Reader r;
    rd_init(r, payload, len);
    rd_u16(r, &out->num_streams);
    rd_string(r, &out->topic);
    return rd_done(r);
}

bool parse_join_session(const uint8_t *payload, uint32_t len, MsgJoinSession *out)
{
    if (out == NULL) return false;
    Reader r;
    rd_init(r, payload, len);
    rd_bytes(r, out->session_id, 16);
    rd_u32(r, &out->conn_id);

    uint32_t bmap_len = 0;
    rd_u32(r, &bmap_len);
    if (!r.ok)
        return false;

    out->chunk_bitmap.clear();
    rd_vector(r, &out->chunk_bitmap, bmap_len);
    return rd_done(r);
}

bool parse_assign_work(const uint8_t *payload, uint32_t len, MsgAssignWork *out)
{
    if (out == NULL) return false;
    Reader r;
    rd_init(r, payload, len);
    rd_u32(r, &out->conn_id);
    rd_u32(r, &out->file_index);
    rd_u64(r, &out->chunk_offset);
    rd_u32(r, &out->chunk_len);
    return rd_done(r);
}

/* ================================================================== */
/* SEND HELPERS - serialize + send_frame in one call                   */
/* ================================================================== */

int send_get(int fd, const std::string &topic)
{
    std::vector<uint8_t> p;
    serialize_get(topic, p);
    return send_frame_vec(fd, OP_GET, p);
}

int send_get_ok(int fd, const uint8_t session_id[16], uint32_t file_count,
                uint64_t total_bytes)
{
    std::vector<uint8_t> p;
    serialize_get_ok(session_id, file_count, total_bytes, p);
    return send_frame_vec(fd, OP_GET_OK, p);
}

int send_error(int fd, uint16_t code, const std::string &reason)
{
    std::vector<uint8_t> p;
    serialize_error(code, reason, p);
    return send_frame_vec(fd, OP_ERROR, p);
}

int send_file_begin(int fd, uint32_t file_index, uint64_t byte_offset,
                    uint64_t bytes_following, const std::string &filename)
{
    std::vector<uint8_t> p;
    serialize_file_begin(file_index, byte_offset, bytes_following, filename, p);
    return send_frame_vec(fd, OP_FILE_BEGIN, p);
}

int send_file_data(int fd, uint32_t file_index, uint64_t offset,
                   const uint8_t *data, uint32_t data_len)
{
    std::vector<uint8_t> p;
    serialize_file_data(file_index, offset, data, data_len, p);
    return send_frame_vec(fd, OP_FILE_DATA, p);
}

int send_file_end(int fd, uint32_t file_index)
{
    std::vector<uint8_t> p;
    serialize_file_end(file_index, p);
    return send_frame_vec(fd, OP_FILE_END, p);
}

int send_transfer_end(int fd, uint32_t files_sent, uint64_t useful_bytes)
{
    std::vector<uint8_t> p;
    serialize_transfer_end(files_sent, useful_bytes, p);
    return send_frame_vec(fd, OP_TRANSFER_END, p);
}

int send_checkpoint_ack(int fd, const uint8_t session_id[16], uint32_t file_index,
                        uint64_t ack_offset)
{
    std::vector<uint8_t> p;
    serialize_checkpoint_ack(session_id, file_index, ack_offset, p);
    return send_frame_vec(fd, OP_CHECKPOINT_ACK, p);
}

int send_resume(int fd, const uint8_t session_id[16], uint32_t file_index,
                uint64_t byte_offset, const std::string &topic,
                const std::string &filename)
{
    std::vector<uint8_t> p;
    serialize_resume(session_id, file_index, byte_offset, topic, filename, p);
    return send_frame_vec(fd, OP_RESUME, p);
}

int send_resume_ok(int fd, uint32_t file_index, uint64_t accepted_offset,
                   uint32_t rem_files, uint64_t rem_bytes)
{
    std::vector<uint8_t> p;
    serialize_resume_ok(file_index, accepted_offset, rem_files, rem_bytes, p);
    return send_frame_vec(fd, OP_RESUME_OK, p);
}

int send_restart(int fd, uint16_t code, const std::string &reason)
{
    std::vector<uint8_t> p;
    serialize_restart(code, reason, p);
    return send_frame_vec(fd, OP_RESTART, p);
}

int send_get_enhanced(int fd, uint16_t num_streams, const std::string &topic)
{
    std::vector<uint8_t> p;
    serialize_get_enhanced(num_streams, topic, p);
    return send_frame_vec(fd, OP_GET_ENHANCED, p);
}

int send_join_session(int fd, const uint8_t session_id[16], uint32_t conn_id,
                      const uint8_t *chunk_bitmap, uint32_t bmap_len)
{
    std::vector<uint8_t> p;
    serialize_join_session(session_id, conn_id, chunk_bitmap, bmap_len, p);
    return send_frame_vec(fd, OP_JOIN_SESSION, p);
}

int send_assign_work(int fd, uint32_t conn_id, uint32_t file_index,
                     uint64_t chunk_offset, uint32_t chunk_len)
{
    std::vector<uint8_t> p;
    serialize_assign_work(conn_id, file_index, chunk_offset, chunk_len, p);
    return send_frame_vec(fd, OP_ASSIGN_WORK, p);
}

/* ================================================================== */
/* Session id helpers                                                  */
/* ================================================================== */

void zero_session_id(uint8_t session_id[16])
{
    memset(session_id, 0, 16);
}

void session_id_to_hex(const uint8_t session_id[16], char out_hex[33])
{
    static const char *digits = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        out_hex[i * 2]     = digits[(session_id[i] >> 4) & 0x0F];
        out_hex[i * 2 + 1] = digits[session_id[i] & 0x0F];
    }
    out_hex[32] = '\0';
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool hex_to_session_id(const char *hex, uint8_t out_session_id[16])
{
    if (hex == NULL || strlen(hex) < 32)
        return false;

    for (int i = 0; i < 16; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out_session_id[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}
