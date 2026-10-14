#ifndef COMMON_TYPES_H
#define COMMON_TYPES_H

/*
 * common_types.h - Shared Header Contract (Group 103 & 106)
 *
 * NOTE: This file is OWNED BY THE GROUP (locked in Phase 0), not by Member 2.
 * It is reproduced here exactly as agreed so that protocol.cpp can be compiled
 * and unit-tested independently. Do not change it without telling the group.
 */

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>
#include <pthread.h>
#include <time.h>

#define PROTOCOL_MAGIC      0x4954              /* "IT" */
#define PROTOCOL_VERSION    0x01
#define MAX_FRAME_PAYLOAD   (1024 * 1024)       /* 1 MB */
#define CHUNK_SIZE          (64 * 1024)         /* 64 KB */

/* Unified Opcodes (Table 2 of Design Doc) */
enum Opcode : uint8_t {
    OP_GET            = 0x01,
    OP_GET_OK         = 0x02,
    OP_ERROR          = 0x03,
    OP_FILE_BEGIN     = 0x04,
    OP_FILE_DATA      = 0x05,
    OP_FILE_END       = 0x06,
    OP_TRANSFER_END   = 0x07,
    OP_CHECKPOINT_ACK = 0x08,
    OP_RESUME         = 0x09,
    OP_RESUME_OK      = 0x0A,
    OP_RESTART        = 0x0B,
    OP_GET_ENHANCED   = 0x0C,
    OP_JOIN_SESSION   = 0x0D,
    OP_ASSIGN_WORK    = 0x0E
};

/* Server Data Structures (Member 1) */
struct FileMeta {
    std::string filename;
    std::string full_path;
    uint64_t    file_size;
};

struct TopicEntry {
    std::string           topic_name;
    std::string           dir_path;
    std::vector<FileMeta> files;        /* Sorted deterministically by filename */
    uint64_t              total_bytes;
};

/* Frame Header (Member 2) */
struct FrameHeader {
    uint16_t magic;
    uint8_t  version;
    uint8_t  type;
    uint32_t payload_length;
};

/* Persistent Checkpoint & Server Session State (Member 4) */
struct CheckpointRecord {
    uint8_t  session_id[16];
    char     session_id_hex[33];
    char     topic[64];
    uint32_t file_index;
    uint64_t byte_offset;
    uint32_t files_done;
    char     file_name[256];
};

struct ServerSession {
    uint8_t  session_id[16];
    char     topic[64];
    uint32_t file_index;
    uint64_t bytes_sent_highwater;
    time_t   last_active;
    bool     all_files_sent;
};

#endif /* COMMON_TYPES_H */
