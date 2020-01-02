#include <netflow9.h>
#include <netinet/in.h>
#include <cstring>
#include <vector>
#include "parse.h"
#include "types.h"

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

int nf9_parse(nf9_state* state, nf9_parse_result** result, const uint8_t* buf,
              size_t len, const nf9_addr* addr)
{
    *result = new nf9_parse_result;
    (*result)->addr = *addr;

    if (!parse(buf, len, state, *result)) {
        state->stats.malformed_packets++;
        nf9_free_parse_result(*result);
        *result = nullptr;
        return 1;
    }

    return 0;
}

size_t nf9_get_num_flowsets(const nf9_parse_result* pr)
{
    return pr->flowsets.size();
}

int nf9_get_flowset_type(const nf9_parse_result* pr, int flowset)
{
    return pr->flowsets[flowset].type;
}

size_t nf9_get_num_flows(const nf9_parse_result* pr, int flowset)
{
    return pr->flowsets[flowset].flows.size();
}

nf9_value nf9_get_field(const nf9_parse_result* pr, int flowset, int flownum,
                        int field)
{
    const std::vector<uint8_t>& value =
        pr->flowsets[flowset].flows[flownum].at(field);

    nf9_value ret;
    switch (value.size()) {
        case sizeof(uint32_t):
            ret.u32 = *reinterpret_cast<const uint32_t*>(value.data());
            break;
        case sizeof(uint64_t):
            ret.u64 = *reinterpret_cast<const uint64_t*>(value.data());
            break;
        default:
            ret.data = {};
            ret.data.bytes = value.data();
            ret.data.length = value.size();
            break;
    }
    return ret;
}

void nf9_free_parse_result(nf9_parse_result* pr)
{
    delete pr;
}

nf9_addr nf9_get_addr(const nf9_parse_result* pr)
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
    switch (stat) {
        case NF9_STAT_TOTAL_RECORDS:
            return stats->records;
        case NF9_STAT_TOTAL_TEMPLATES:
            return stats->templates;
        case NF9_STAT_TOTAL_OPTION_TEMPLATES:
            return stats->option_templates;
        case NF9_STAT_MALFORMED_PACKETS:
            return stats->malformed_packets;
    }
    return 0;
}

void nf9_free_stats(const nf9_stats* stats)
{
    delete stats;
}
