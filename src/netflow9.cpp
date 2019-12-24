#include "netflow9.h"
#include <netinet/in.h>

struct nf9_state
{
};

nf9_state* nf9_init(int flags)
{
    return NULL;
}

void nf9_free(nf9_state* state)
{
}

struct nf9_parse_result
{
};

int nf9_parse(nf9_state* state, nf9_parse_result** result, const uint8_t* buf,
              size_t len, const struct sockaddr* addr)
{
    return 0;
}

size_t nf9_get_num_flowsets(const nf9_parse_result* pr)
{
    return 0;
}

size_t nf9_get_num_flows(const nf9_parse_result* pr, int flowset)
{
    return 0;
}

nf9_value nf9_get_field(const nf9_parse_result* pr, int flowset, int flow,
                        int field)
{
    nf9_value v;
    v.u32 = 0;
    return v;
}

void nf9_free_parse_result(nf9_parse_result* pr)
{
}

sockaddr nf9_get_addr(const nf9_parse_result* pr)
{
    sockaddr_in address = {};
    return *reinterpret_cast<sockaddr*>(&address);
}

struct nf9_stats
{
};

const nf9_stats* nf9_get_stats(const nf9_state* state)
{
    return NULL;
}

int nf9_get_stat(const nf9_stats* stats, int stat)
{
    return 0;
}

void nf9_free_stats(const nf9_stats* stats)
{
}
