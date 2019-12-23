#ifndef NETFLOW9_H
#define NETFLOW9_H

#include <stddef.h>
#include <stdint.h>

#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

enum nf9_state_flags {
    NF9_THREAD_SAFE = 1,
};
typedef struct nf9_state nf9_state;

nf9_state* nf9_init(int flags);
void nf9_free(nf9_state* state);

typedef struct nf9_parse_result nf9_parse_result;

int nf9_parse(nf9_state* state, nf9_parse_result** result, const uint8_t* buf,
              size_t len, const struct sockaddr* peer, socklen_t peer_len);

void nf9_free_parse_result(nf9_parse_result* result);

enum nf9_field {
    NF9_FIELD_PACKETS,
};
union nf9_value {
    uint16_t word;
    uint32_t dword;
    uint64_t qword;
    struct
    {
        uint64_t upper64;
        uint64_t lower64;
    } dqword;
    struct
    {
        size_t length;
        void* bytes;
    } data;
};

size_t nf9_get_num_flowsets(const nf9_parse_result* pr);
size_t nf9_get_num_flows(const nf9_parse_result* pr, int flowset);
nf9_value nf9_get_field(const nf9_parse_result* pr, int flowset, int flow,
                        int field);

typedef struct nf9_stats nf9_stats;

const nf9_stats* nf9_get_stats(const nf9_state* state);

#ifdef __cplusplus
}
#endif

#endif  // NETFLOW9_H
