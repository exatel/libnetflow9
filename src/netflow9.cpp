/*
 * Copyright © 2019-2020 Exatel S.A.
 * Contact: opensource@exatel.pl
 * LICENSE: LGPL-3.0-or-later, See COPYING*.md files.
 */

#include <netflow9.h>
#include <netinet/in.h>
#include <climits>
#include <cstring>
#include <mutex>
#include <vector>
#include "decode.h"
#include "types.h"

const char* nf9_strerror(int err)
{
    switch (err) {
        case 0:
            return "success";
        case NF9_ERR_INVALID_ARGUMENT:
            return "invalid argument";
        case NF9_ERR_NOT_FOUND:
            return "field not found";
        case NF9_ERR_OUT_OF_MEMORY:
            return "out of memory";
        case NF9_ERR_MALFORMED:
            return "malformed packet";
        case NF9_ERR_OUTDATED:
            return "entity is outdated";
        default:
            return "unknown error";
    }
}

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
        /*store_samplings=*/bool(flags & NF9_STORE_SAMPLING_RATES),
        /*sampling_rates=*/pmr::unordered_map<sampler_id, uint32_t>(addr),
        /*simple_sampling_rates=*/
        pmr::unordered_map<simple_sampler_id, uint32_t>(addr),
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
    state->stats.processed_packets++;

    if (int err = decode(buf, len, *addr, state, *result); err != 0) {
        state->stats.malformed_packets++;
        nf9_free_packet(*result);
        *result = nullptr;
        return err;
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

uint32_t nf9_get_source_id(const nf9_packet* pkt)
{
    return pkt->src_id;
}

uint32_t nf9_get_uptime(const nf9_packet* pkt)
{
    return pkt->system_uptime;
}

int nf9_get_field(const nf9_packet* pkt, unsigned flowset, unsigned flownum,
                  nf9_field field, void* dst, size_t* length)
{
    if (flowset >= pkt->flowsets.size())
        return NF9_ERR_INVALID_ARGUMENT;
    if (flownum >= pkt->flowsets[flowset].flows.size())
        return NF9_ERR_INVALID_ARGUMENT;
    if (pkt->flowsets[flowset].flows[flownum].count(field) == 0)
        return NF9_ERR_NOT_FOUND;
    const pmr::vector<uint8_t>& value =
        pkt->flowsets[flowset].flows[flownum].at(field);

    if (*length < value.size())
        return NF9_ERR_INVALID_ARGUMENT;

    memcpy(dst, value.data(), value.size());
    *length = value.size();

    return 0;
}

int nf9_get_all_fields(const nf9_packet* pkt, unsigned flowset,
                       unsigned flownum, nf9_fieldval* out, size_t* size)
{
    if (flowset >= pkt->flowsets.size())
        return NF9_ERR_INVALID_ARGUMENT;
    if (flownum >= pkt->flowsets[flowset].flows.size())
        return NF9_ERR_INVALID_ARGUMENT;

    size_t i = 0;
    for (const auto& [key, val] : pkt->flowsets[flowset].flows[flownum]) {
        if (i >= *size)
            break;
        out[i].field = key;
        out[i].size = val.size();
        out[i].value = val.data();
        ++i;
    }

    *size = i;
    return 0;
}

int nf9_get_option(const nf9_packet* pkt, nf9_field field, void* dst,
                   size_t* length)
{
    std::lock_guard<std::mutex> lock(pkt->state->options_mutex);
    device_id dev_id = {pkt->addr, pkt->src_id};
    if (pkt->state->options.count(dev_id) == 0)
        return NF9_ERR_NOT_FOUND;
    if (pkt->state->options.at(dev_id).options_flow.count(field) == 0)
        return NF9_ERR_NOT_FOUND;

    const pmr::vector<uint8_t>& value =
        pkt->state->options.at(dev_id).options_flow.at(field);

    if (*length < value.size())
        return NF9_ERR_INVALID_ARGUMENT;

    memcpy(dst, value.data(), value.size());
    *length = value.size();

    return 0;
}

int nf9_get_sampling_rate(const nf9_packet* pkt, unsigned flowset,
                          unsigned flownum, uint32_t* sampling,
                          int* sampling_info)
{
    bool set_sampling_info = true;
    if (sampling_info == nullptr)
        set_sampling_info = false;

    const nf9_state* st = pkt->state;
    if (!st->store_sampling_rates)
        return NF9_ERR_INVALID_ARGUMENT;

    // Get SAMPLER_ID from the flow
    uint32_t stored_sid;
    size_t len = sizeof(stored_sid);
    if (nf9_get_field(pkt, flowset, flownum, NF9_FIELD_FLOW_SAMPLER_ID,
                      &stored_sid, &len)) {
        if (set_sampling_info)
            *sampling_info = NF9_SAMPLING_SAMPLER_ID_NOT_FOUND;
        return NF9_ERR_NOT_FOUND;
    }

#ifdef NF9_IS_BIG_ENDIAN
    stored_sid >>= (sizeof(stored_sid) - len) * CHAR_BIT;
#else
    stored_sid <<= (sizeof(stored_sid) - len) * CHAR_BIT;
#endif
    stored_sid = ntohl(stored_sid);

    // Lookup the value in stored sampling rates
    device_id dev_id = {pkt->addr, pkt->src_id};
    sampler_id sid = {dev_id, stored_sid};
    if (auto sid_it = st->sampling_rates.find(sid);
        sid_it != st->sampling_rates.end()) {
        *sampling = sid_it->second;
        if (set_sampling_info)
            *sampling_info = NF9_SAMPLING_MATCH_IP_SOURCE_ID_SAMPLER_ID;
        return 0;
    }

    // Lookup the value in stored simple sampling rates -
    // don't match by source_id
    simple_sampler_id simple_sid = {dev_id.addr, stored_sid};
    if (auto simple_sid_it = st->simple_sampling_rates.find(simple_sid);
        simple_sid_it != st->simple_sampling_rates.end()) {
        *sampling = simple_sid_it->second;
        if (set_sampling_info)
            *sampling_info = NF9_SAMPLING_MATCH_IP_SAMPLER_ID;
        return 0;
    }

    if (set_sampling_info)
        *sampling_info = NF9_SAMPLING_OPTION_RECORD_NOT_FOUND;
    return NF9_ERR_NOT_FOUND;
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
        case NF9_STAT_PROCESSED_PACKETS:
            return stats->processed_packets;
        case NF9_STAT_MALFORMED_PACKETS:
            return stats->malformed_packets;
        case NF9_STAT_TOTAL_RECORDS:
            return stats->records;
        case NF9_STAT_TOTAL_DATA_TEMPLATES:
            return stats->data_templates;
        case NF9_STAT_TOTAL_OPTION_TEMPLATES:
            return stats->option_templates;
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
                return NF9_ERR_INVALID_ARGUMENT;
            }
        case NF9_OPT_TEMPLATE_EXPIRE_TIME:
            if (value > 0) {
                state->template_expire_time = static_cast<uint32_t>(value);
                return 0;
            }
            else {
                return NF9_ERR_INVALID_ARGUMENT;
            }
        case NF9_OPT_OPTION_EXPIRE_TIME:
            if (value > 0) {
                state->option_expire_time = static_cast<uint32_t>(value);
                return 0;
            }
            else {
                return NF9_ERR_INVALID_ARGUMENT;
            }
    }
    return NF9_ERR_INVALID_ARGUMENT;
}

size_t hash_nf9addr_id(const nf9_addr& addr, uint32_t id) noexcept
{
    size_t ret = id;

    switch (addr.family) {
        case AF_INET:
            ret ^= addr.in.sin_addr.s_addr;
            ret ^= uint32_t(addr.in.sin_port) << 16;
            break;
        case AF_INET6: {
            // FIXME: The IPv6 address should be normalized here, this is not
            // reliable.
            const sockaddr_in6& addr_in = addr.in6;
            const size_t* parts =
                reinterpret_cast<const size_t*>(&addr_in.sin6_addr);
            const size_t n = sizeof(addr_in.sin6_addr) / sizeof(size_t);
            for (size_t i = 0; i < n; i++)
                ret ^= parts[i];
            ret ^= addr_in.sin6_port;
            break;
        }
        default:
            break;
    }

    return ret;
}

template <typename T>
bool compare_nf9addr_id(const T& lhs, const T& rhs) noexcept
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

size_t std::hash<device_id>::operator()(const device_id& dev_id) const noexcept
{
    return hash_nf9addr_id(dev_id.addr, dev_id.id);
}

bool operator==(const device_id& lhs, const device_id& rhs) noexcept
{
    return compare_nf9addr_id(lhs, rhs);
}

size_t std::hash<stream_id>::operator()(const stream_id& sid) const noexcept
{
    size_t ret = std::hash<device_id>()(sid.dev_id);
    ret |= sid.tid << 16;

    return ret;
}

bool operator==(const stream_id& lhs, const stream_id& rhs) noexcept
{
    return lhs.dev_id == rhs.dev_id && lhs.tid == rhs.tid;
}

size_t std::hash<sampler_id>::operator()(const sampler_id& sid) const noexcept
{
    size_t ret = std::hash<device_id>()(sid.did);
    ret ^= std::hash<uint16_t>()(sid.sid);

    return ret;
}

bool operator==(const sampler_id& lhs, const sampler_id& rhs) noexcept
{
    return lhs.did == rhs.did && lhs.sid == rhs.sid;
}

size_t std::hash<simple_sampler_id>::operator()(
    const simple_sampler_id& simple_sid) const noexcept
{
    return hash_nf9addr_id(simple_sid.addr, simple_sid.id);
}

bool operator==(const simple_sampler_id& lhs,
                const simple_sampler_id& rhs) noexcept
{
    return compare_nf9addr_id(lhs, rhs);
}
