#include <netflow9.h>
#include <netinet/in.h>
#include <cstring>
#include <vector>
#include "types.h"

enum class nf9_rc { RESULT_OK, RESULT_ERR };

nf9_rc parse_nf_hdr(const uint8_t* buf, size_t len, struct nf9_packet* packet)
{
    if (len < sizeof(struct nf9_packet))
        return nf9_rc::RESULT_ERR;
    memcpy(packet, buf, sizeof(struct nf9_packet));
    packet->payload_ = buf + sizeof(nf9_header);

    return packet->header().is_well_formed() ? nf9_rc::RESULT_OK
                                             : nf9_rc::RESULT_ERR;
}

nf9_rc parse_nf_flowset(nf9_state* state, const uint8_t* buf, size_t len,
                        struct nf9_packet* packet, nf9_parse_result* result)
{
    const uint8_t* end = buf + len;
    buf += sizeof(nf9_header);
    uint16_t i = 0;
    while (buf <= end - sizeof(struct nf9_flowset_header) &&
           i < packet->header().record_count()) {
        struct nf9_flowset_header flowset_info = {};
        memcpy(&flowset_info, buf, sizeof(struct nf9_flowset_header));
        if (flowset_info.length() <= 4)
            return nf9_rc::RESULT_ERR;

        switch (flowset_info.record_type()) {
            case RecordType::TEMPLATE:
                state->stats.templates++;
                result->flowsets.push_back(flowset{NF9_FLOWSET_TEMPLATE});
                break;
            case RecordType::OPTIONS:
                state->stats.option_templates++;
                result->flowsets.push_back(flowset{NF9_FLOWSET_OPTIONS});
                break;
            case RecordType::DATA:
                state->stats.records++;
                result->flowsets.push_back(flowset{NF9_FLOWSET_DATA});
                break;
            default:
                break;
        }

        buf += flowset_info.length();
        ++i;
    }
    if (buf > end)
        return nf9_rc::RESULT_ERR;
    return nf9_rc::RESULT_OK;
}

nf9_rc parse(nf9_state* state, const uint8_t* buf, size_t len,
             struct nf9_packet* packet, nf9_parse_result* result)
{
    if (nf9_rc::RESULT_OK != parse_nf_hdr(buf, len, packet))
        return nf9_rc::RESULT_ERR;

    if (nf9_rc::RESULT_OK != parse_nf_flowset(state, buf, len, packet, result))
        return nf9_rc::RESULT_ERR;

    return nf9_rc::RESULT_OK;
}

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
    struct nf9_packet packet = {};

    auto result_ = parse(state, buf, len, &packet, *result);
    if (result_ != nf9_rc::RESULT_OK) {
        state->stats.malformed_packets++;
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
