#include <netinet/in.h>
#include <vector>
#include "netflow9.h"

struct nf9_stats
{
    int processed_packets = 0;
    int malformed_packets = 0;
    int records = 0;
    int templates = 0;
    int option_templates = 0;
    int missing_template_errors = 0;
};

struct nf9_state
{
    int flags;
    nf9_stats stats;
};

nf9_state* nf9_init(int flags)
{
    nf9_state* st = new nf9_state;
    st->flags = flags;
    return st;
}

void nf9_free(nf9_state* state)
{
    delete state;
}

struct flowset
{
    nf9_flowset_type type;
};

struct nf9_parse_result
{
    std::vector<flowset> flowsets;
    sockaddr addr;
};

int nf9_parse(nf9_state* state, nf9_parse_result** result, const uint8_t* buf,
              size_t len, const struct sockaddr* addr)
{
    *result = new nf9_parse_result;
    (*result)->addr = *addr;
    return 0;
}

size_t nf9_get_num_flowsets(const nf9_parse_result* pr)
{
    return 0;
}

int nf9_get_flowset_type(const nf9_parse_result* pr, int flowset)
{
    return pr->flowsets[flowset].type;
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
    delete pr;
}

sockaddr nf9_get_addr(const nf9_parse_result* pr)
{
    return pr->addr;
}

const nf9_stats* nf9_get_stats(const nf9_state* state)
{
    nf9_stats* stats = new nf9_stats;
    *stats = state->stats;
    return stats;
}

int nf9_get_stat(const nf9_stats* stats, int stat)
{
    return 0;
}

void nf9_free_stats(const nf9_stats* stats)
{
    delete stats;
}
