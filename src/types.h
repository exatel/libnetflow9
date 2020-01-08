#ifndef TYPES_H
#define TYPES_H

#include <netflow9.h>
#include <netinet/in.h>
#include <unordered_map>
#include <vector>
#include <variant>

struct nf9_stats
{
    int processed_packets = 0;
    int malformed_packets = 0;
    int records = 0;
    int templates = 0;
    int option_templates = 0;
    int missing_template_errors = 0;
};

using template_field = std::pair<int, int>;
using flow = std::unordered_map<int, std::vector<uint8_t>>;

struct data_template
{
    std::vector<template_field> fields;
    size_t total_length;
};

/* Objects of this type uniquely identify flow streams across all
 * exporter devices by using a combination of the exporter source IP
 * address, the source_id field in the Netflow header, and template id. */
struct exporter_stream_id
{
    nf9_addr addr;
    uint32_t id;
    uint16_t tid;
};

namespace std
{
template <>
struct hash<exporter_stream_id>
{
    size_t operator()(const exporter_stream_id&) const noexcept;
};
}  // namespace std

bool operator==(const exporter_stream_id&, const exporter_stream_id&) noexcept;

/* Objects of this type uniquely identify flow streams across all
 * exporter devices by using a combination of the exporter source IP
 * address, the source_id field in the Netflow header, and template id. */
struct exporter_stream_id
{
    nf9_addr addr;
    uint32_t id;
    uint16_t tid;
};

namespace std
{
template <>
struct hash<exporter_stream_id>
{
    size_t operator()(const exporter_stream_id&) const noexcept;
};
}  // namespace std

bool operator==(const exporter_stream_id&, const exporter_stream_id&) noexcept;

struct nf9_state
{
    int flags;
    nf9_stats stats;

    /* FIXME: The map key should recognize the exporter device
     * (nf9_addr.) */
    std::unordered_map<int, data_template> templates;
    std::unordered_map<int, option_template> option_templates;
};

struct flowset
{
    nf9_flowset_type type;

    /* Empty if this is not a data template flowset. */
    data_template dtemplate;

    /* Empty if this is not a option template flowset. */
    option_template otemplate;

    /* This contains flows in data records.  Empty if this is not a data record
     * flowset. */
    std::vector<flow> flows;

    // TODO - change to variant? Other way of structure initialisation
    // already deleted compile warnings.
    // std::variant<data_template, option_template, std::vector<flow>> myk;
};

struct nf9_parse_result
{
    std::vector<flowset> flowsets;
    nf9_addr addr;
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
