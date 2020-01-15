#include <netflow9.h>
#include <netinet/in.h>
#include <cstring>
#include <vector>
#include "parse.h"
#include "types.h"

nf9_state* nf9_init(int flags)
{
    nf9_state* st = new nf9_state();
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

    if (!parse(buf, len, *addr, state, *result)) {
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

int nf9_get_field(const nf9_parse_result* pr, int flowset, int flownum,
                  nf9_field field, void* dst, size_t* length)
{
    if (flowset >= pr->flowsets.size())
        return 1;
    if (flownum >= pr->flowsets[flowset].flows.size())
        return 1;
    if (pr->flowsets[flowset].flows[flownum].count(field) == 0)
        return 1;
    const std::vector<uint8_t>& value =
        pr->flowsets[flowset].flows[flownum].at(field);

    if (*length < value.size())
        return 1;

    memcpy(dst, value.data(), value.size());
    *length = value.size();

    return 0;
}

void nf9_free_parse_result(const nf9_parse_result* pr)
{
    delete pr;
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
        case NF9_STAT_TOTAL_DATA_TEMPLATES:
            return stats->data_templates;
        case NF9_STAT_TOTAL_OPTION_TEMPLATES:
            return stats->option_templates;
        case NF9_STAT_MALFORMED_PACKETS:
            return stats->malformed_packets;
        case NF9_STAT_MISSING_TEMPLATE_ERRORS:
            return stats->missing_template_errors;
        case NF9_STAT_EXPIRED_TEMPLATES:
            return stats->expired_templates;
    }
    return 0;
}

void nf9_free_stats(const nf9_stats* stats)
{
    delete stats;
}

int nf9_set_option(nf9_state* state, nf9_opt opt, long value)
{
    switch (opt) {
        case NF9_OPT_MAX_MEM_USAGE:
            if (value > 0) {
                state->max_template_data = static_cast<size_t>(value);
                return 0;
            }
            else {
                return 1;
            }
        case NF9_OPT_TEMPLATE_EXPIRE_TIME:
            if (value > 0) {
                state->template_expire_time = static_cast<uint32_t>(value);
                return 0;
            }
            else {
                return 1;
            }
    }
    return 1;
}

size_t std::hash<exporter_stream_id>::operator()(
    const exporter_stream_id& sid) const noexcept
{
    size_t ret = sid.id;
    ret |= sid.tid << 16;

    switch (sid.addr.family) {
        case AF_INET:
            ret ^= sid.addr.in.sin_addr.s_addr;
            ret ^= uint32_t(sid.addr.in.sin_port) << 16;
            break;
        case AF_INET6: {
            // FIXME: The IPv6 address should be normalized here, this is not
            // reliable.
            const sockaddr_in6& addr = sid.addr.in6;
            const size_t* parts =
                reinterpret_cast<const size_t*>(&addr.sin6_addr);
            const size_t n = sizeof(addr.sin6_addr) / sizeof(size_t);
            for (size_t i = 0; i < n; i++)
                ret ^= parts[i];
            ret ^= addr.sin6_port;
            break;
        }
        default:
            break;
    }

    return ret;
}

bool operator==(const exporter_stream_id& lhs,
                const exporter_stream_id& rhs) noexcept
{
    if (lhs.id != rhs.id || lhs.tid != rhs.tid ||
        lhs.addr.family != rhs.addr.family)
        return false;

    switch (lhs.addr.family) {
        case AF_INET:
            return lhs.addr.in.sin_addr.s_addr == rhs.addr.in.sin_addr.s_addr &&
                   lhs.addr.in.sin_port == rhs.addr.in.sin_port;
        case AF_INET6:
            // FIXME: The IPv6 address should be normalized here, this is not
            // reliable.
            return memcmp(&lhs.addr.in6.sin6_addr, &rhs.addr.in6.sin6_addr,
                          sizeof(lhs.addr.in6.sin6_addr)) == 0 &&
                   lhs.addr.in6.sin6_port == rhs.addr.in6.sin6_port;
    }
    return true;
}
