#ifndef TYPES_H
#define TYPES_H

#include <netflow9.h>
#include <netinet/in.h>
#include <unordered_map>
#include <vector>

struct nf9_stats
{
    int processed_packets = 0;
    int malformed_packets = 0;
    int records = 0;
    int data_templates = 0;
    int option_templates = 0;
    int missing_template_errors = 0;
    int expired_templates = 0;

    size_t memory_usage = 0;
};

using template_field = std::pair<nf9_field, int>;
using flow = std::unordered_map<int, std::vector<uint8_t>>;

struct data_template
{
    std::vector<template_field> fields;
    size_t total_length;
    uint32_t timestamp;
    bool is_option;
};

struct device_options
{
    flow options_flow;
    uint32_t timestamp;
};

/*
 * Collector devices should use the combination of the source IP address plus
 * the Source ID field to associate an incoming NetFlow export packet with a
 * unique instance of NetFlow on a particular device.
 */
struct device_id
{
    nf9_addr addr;
    uint32_t id;
};

/*
 * Objects of this type uniquely identify flow streams across all
 * exporter devices by using a combination of the exporter source IP
 * address, the source_id field in the Netflow header, and template id.
 */
struct stream_id
{
    device_id dev_id;
    uint16_t tid;
};

namespace std
{
template <>
struct hash<stream_id>
{
    size_t operator()(const stream_id &) const noexcept;
};

template <>
struct hash<device_id>
{
    size_t operator()(const device_id &) const noexcept;
};
}  // namespace std

bool operator==(const stream_id &, const stream_id &) noexcept;
bool operator==(const device_id &, const device_id &) noexcept;

static const size_t MAX_TEMPLATE_DATA = 10000;
static const uint32_t TEMPLATE_EXPIRE_TIME = 15 * 60;

struct nf9_state
{
    int flags;
    nf9_stats stats;
    size_t max_template_data = MAX_TEMPLATE_DATA;
    uint32_t template_expire_time = TEMPLATE_EXPIRE_TIME;

    /* Counter of bytes alocated in templates unordered_map */
    size_t used_bytes = 0;

    std::unordered_map<stream_id, data_template> templates;
    std::unordered_map<device_id, device_options> options;
};

struct flowset
{
    nf9_flowset_type type;

    /* Empty if this is not a data template flowset. */
    data_template dtemplate;

    /* This contains flows in data records.  Empty if this is not a data record
     * flowset. */
    std::vector<flow> flows;
};

struct nf9_parse_result
{
    std::vector<flowset> flowsets;
    nf9_addr addr;
    uint32_t src_id;
    uint32_t system_uptime;
    uint32_t timestamp;
    nf9_state *state;
};

struct netflow_header
{
    uint16_t version;
    uint16_t count;
    uint32_t uptime;
    uint32_t timestamp;
    uint32_t sequence;
    uint32_t source_id;
};

#endif
