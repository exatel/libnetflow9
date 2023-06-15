/*
 * Copyright © 2019-2020 Exatel S.A.
 * Contact: opensource@exatel.pl
 * LICENSE: LGPL-3.0-or-later, See COPYING*.md files.
 */

#ifndef TYPES_H
#define TYPES_H

#include <netflow9.h>
#include <netinet/in.h>
#include <iostream>
#include <mutex>
#include <memory> // unique_ptr

#include "config.h"

#ifdef NF9_HAVE_MEMORY_RESOURCE
#include <memory_resource>
#include <unordered_map>
#include <vector>

namespace pmr = std::pmr;

#elif defined(NF9_HAVE_EXPERIMENTAL_MEMORY_RESOURCE)
#include <experimental/memory_resource>
#include <experimental/unordered_map>
#include <experimental/vector>

namespace pmr = std::experimental::pmr;

#else
#error "<memory_resource> not found"
#endif

struct nf9_stats
{
    unsigned processed_packets = 0;
    unsigned malformed_packets = 0;
    unsigned records = 0;
    unsigned data_templates = 0;
    unsigned option_templates = 0;
    unsigned missing_template_errors = 0;
    unsigned expired_templates = 0;

    size_t memory_usage = 0;
};

using template_field = std::pair<nf9_field, uint16_t>;
using flow = pmr::unordered_map<nf9_field, pmr::vector<uint8_t>>;

struct data_template
{
    pmr::vector<template_field> fields;
    size_t total_length;
    uint32_t timestamp;
    bool is_option;
};

static const size_t MAX_MEMORY_USAGE = 10000;
static const uint32_t TEMPLATE_EXPIRE_TIME = 5 * 60;
static const uint32_t OPTION_EXPIRE_TIME = 15 * 60;

class limited_memory_resource : public pmr::memory_resource
{
public:
    limited_memory_resource(size_t max_size) : max_size_(max_size), used_(0){};
    limited_memory_resource(const limited_memory_resource &other) = delete;
    limited_memory_resource(limited_memory_resource &&other) = delete;

    virtual void *do_allocate(std::size_t bytes,
                              std::size_t alignment) override;

    virtual void do_deallocate(void *p, std::size_t bytes,
                               std::size_t alignment) override;

    virtual bool do_is_equal(const pmr::memory_resource &other) const
        noexcept override;

    size_t get_current() const;

    void set_limit(size_t max_mem);

private:
    /* Max memory allocation in bytes */
    size_t max_size_;

    /* Counter of allocated bytes*/
    size_t used_;
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
 * address, the source_id field in the NetFlow header, and template id.
 */
struct stream_id
{
    device_id dev_id;
    uint16_t tid;
};

/*
 * Uniquely identifies a sampler accross all exporter devices.
 */
struct sampler_id
{
    device_id did;
    uint32_t sid;
};

/*
 * Identifies a sampler using only IP address and Sampler ID
 */
struct simple_sampler_id
{
    nf9_addr addr;
    uint32_t id;
};

template <>
struct std::hash<stream_id>
{
    size_t operator()(const stream_id &) const noexcept;
};

template <>
struct std::hash<device_id>
{
    size_t operator()(const device_id &) const noexcept;
};

template <>
struct std::hash<sampler_id>
{
    size_t operator()(const sampler_id &) const noexcept;
};

template <>
struct std::hash<simple_sampler_id>
{
    size_t operator()(const simple_sampler_id &) const noexcept;
};

bool operator==(const stream_id &, const stream_id &) noexcept;
bool operator==(const device_id &, const device_id &) noexcept;
bool operator==(const sampler_id &, const sampler_id &) noexcept;
bool operator==(const simple_sampler_id &, const simple_sampler_id &) noexcept;

struct nf9_state
{
    int flags;
    nf9_stats stats;
    uint32_t template_expire_time;
    uint32_t option_expire_time;
    std::unique_ptr<limited_memory_resource> memory;

    pmr::unordered_map<stream_id, data_template> templates;
    pmr::unordered_map<device_id, device_options> options;

    /* Mutex for options unordered_map */
    std::mutex options_mutex;

    bool store_sampling_rates;
    pmr::unordered_map<sampler_id, uint32_t> sampling_rates;
    pmr::unordered_map<simple_sampler_id, uint32_t> simple_sampling_rates;
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

struct nf9_packet
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
