/*
 * Copyright © 2019-2020 Exatel S.A.
 * Contact: github@exatel.pl
 * LICENSE: LGPL-3.0-or-later, See COPYING*.md files.
 */

#include <netflow9.h>
#include <netinet/in.h>
#include <cstring>
#include <mutex>
#include <vector>
#include "decode.h"
#include "types.h"

nf9_state* nf9_init(int flags)
{
    std::unique_ptr mr =
        std::make_unique<limited_memory_resource>(MAX_MEMORY_USAGE);
    auto* addr = mr.get();
    nf9_state* st = new nf9_state{
        /*flags=*/flags,
        /*stats=*/{},
        /*template_expire_time=*/TEMPLATE_EXPIRE_TIME,
        /*option_expire_time=*/OPTION_EXPIRE_TIME,
        /*memory=*/std::move(mr),
        /*templates=*/
        pmr::unordered_map<stream_id, data_template>(addr),
        /*options=*/
        pmr::unordered_map<device_id, device_options>(addr),
        /*options_mutex=*/{},
    };

    return st;
}

void nf9_free(nf9_state* state)
{
    delete state;
}

int nf9_decode(nf9_state* state, nf9_packet** result, const uint8_t* buf,
               size_t len, const nf9_addr* addr)
{
    *result = new nf9_packet;
    (*result)->addr = *addr;
    (*result)->state = state;

    if (!decode(buf, len, *addr, state, *result)) {
        state->stats.malformed_packets++;
        nf9_free_packet(*result);
        *result = nullptr;
        return 1;
    }

    return 0;
}

size_t nf9_get_num_flowsets(const nf9_packet* pkt)
{
    return pkt->flowsets.size();
}

int nf9_get_flowset_type(const nf9_packet* pkt, unsigned flowset)
{
    return pkt->flowsets[flowset].type;
}

size_t nf9_get_num_flows(const nf9_packet* pkt, unsigned flowset)
{
    return pkt->flowsets[flowset].flows.size();
}

uint32_t nf9_get_timestamp(const nf9_packet* pkt)
{
    return pkt->timestamp;
}

uint32_t nf9_get_uptime(const nf9_packet* pkt)
{
    return pkt->system_uptime;
}

int nf9_get_field(const nf9_packet* pkt, unsigned flowset, unsigned flownum,
                  nf9_field field, void* dst, size_t* length)
{
    if (flowset >= pkt->flowsets.size())
        return 1;
    if (flownum >= pkt->flowsets[flowset].flows.size())
        return 1;
    if (pkt->flowsets[flowset].flows[flownum].count(field) == 0)
        return 1;
    const pmr::vector<uint8_t>& value =
        pkt->flowsets[flowset].flows[flownum].at(field);

    if (*length < value.size())
        return 1;

    memcpy(dst, value.data(), value.size());
    *length = value.size();

    return 0;
}

int nf9_get_option(const nf9_packet* pkt, nf9_field field, void* dst,
                   size_t* length)
{
    std::lock_guard<std::mutex> lock(pkt->state->options_mutex);
    device_id dev_id = {pkt->addr, pkt->src_id};
    if (pkt->state->options.count(dev_id) == 0)
        return 1;
    if (pkt->state->options.at(dev_id).options_flow.count(field) == 0)
        return 1;

    const pmr::vector<uint8_t>& value =
        pkt->state->options.at(dev_id).options_flow.at(field);

    if (*length < value.size())
        return 1;

    memcpy(dst, value.data(), value.size());
    *length = value.size();

    return 0;
}

void nf9_free_packet(const nf9_packet* pkt)
{
    delete pkt;
}

const nf9_stats* nf9_get_stats(const nf9_state* state)
{
    nf9_stats* stats = new nf9_stats;
    *stats = state->stats;
    stats->memory_usage = state->memory->get_current();
    return stats;
}

uint64_t nf9_get_stat(const nf9_stats* stats, int stat)
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
        case NF9_STAT_EXPIRED_OBJECTS:
            return stats->expired_templates;
        case NF9_STAT_MEMORY_USAGE:
            return stats->memory_usage;
    }
    return 0;
}

void nf9_free_stats(const nf9_stats* stats)
{
    delete stats;
}

int nf9_ctl(nf9_state* state, int opt, long value)
{
    switch (opt) {
        case NF9_OPT_MAX_MEM_USAGE:
            if (value > 0) {
                state->memory->set_limit(static_cast<size_t>(value));
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
        case NF9_OPT_OPTION_EXPIRE_TIME:
            if (value > 0) {
                state->option_expire_time = static_cast<uint32_t>(value);
                return 0;
            }
            else {
                return 1;
            }
    }
    return 1;
}

size_t std::hash<device_id>::operator()(const device_id& dev_id) const noexcept
{
    size_t ret = dev_id.id;

    switch (dev_id.addr.family) {
        case AF_INET:
            ret ^= dev_id.addr.in.sin_addr.s_addr;
            ret ^= uint32_t(dev_id.addr.in.sin_port) << 16;
            break;
        case AF_INET6: {
            // FIXME: The IPv6 address should be normalized here, this is not
            // reliable.
            const sockaddr_in6& addr = dev_id.addr.in6;
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

bool operator==(const device_id& lhs, const device_id& rhs) noexcept
{
    if (lhs.id != rhs.id || lhs.addr.family != rhs.addr.family)
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

size_t std::hash<stream_id>::operator()(const stream_id& sid) const noexcept
{
    size_t ret = std::hash<device_id>()(sid.dev_id);
    ret |= sid.tid << 16;

    return ret;
}

bool operator==(const stream_id& lhs, const stream_id& rhs) noexcept
{
    if (!(lhs.dev_id == rhs.dev_id) || lhs.tid != rhs.tid)
        return false;

    return true;
}
