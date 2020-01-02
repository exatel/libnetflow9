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
    int templates = 0;
    int option_templates = 0;
    int missing_template_errors = 0;
};

using template_field = std::pair<int, int>;
using data_template = std::vector<template_field>;

struct nf9_state
{
    int flags;
    nf9_stats stats;

    /* FIXME: The map key should recognize the exporter device
     * (nf9_addr.) */
    std::unordered_map<int, data_template> templates;
};

struct flowset
{
    nf9_flowset_type type;
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

struct flowset_header
{
    uint16_t flowset_id;
    uint16_t length;
};

#endif
