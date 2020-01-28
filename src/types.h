#ifndef TYPES_H
#define TYPES_H

#include <netflow9.h>
#include <netinet/in.h>
#include <iostream>
#include <vector>

#include "config.h"

#ifdef NF9_HAVE_MEMORY_RESOURCE
#include <memory_resource>
#include <unordered_map>

namespace nf9_std_pmr {
using namespace std::pmr;
}

#elif defined(NF9_HAVE_EXPERIMENTAL_MEMORY_RESOURCE)
#include <experimental/memory_resource>
#include <experimental/unordered_map>

namespace nf9_std_pmr {
using namespace std::experimental::pmr;
}

#else
#error "<memory_resource> not found"
#endif

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

static const size_t MAX_TEMPLATE_DATA = 10000;
static const uint32_t TEMPLATE_EXPIRE_TIME = 15 * 60;

class umap_resource : public nf9_std_pmr::memory_resource
{
public:
    umap_resource(size_t max_size) : max_size_(max_size)
    {
        used_ = 0;
    };
    umap_resource(const umap_resource &other) = delete;
    umap_resource(umap_resource &&other) = delete;
    //: max_size_(other.max_size_), used_(other.used_){};

    virtual void *do_allocate(std::size_t bytes, std::size_t alignment) override
    {
        if (bytes > max_size_ - used_)
            throw std::bad_alloc();
        nf9_std_pmr::memory_resource *mr =
            nf9_std_pmr::new_delete_resource();
        void *result = mr->allocate(bytes, alignment);
        used_ += bytes;
        return result;
    };

    virtual void do_deallocate(void *p, std::size_t bytes,
                               std::size_t alignment) override
    {
        nf9_std_pmr::memory_resource *mr =
            nf9_std_pmr::new_delete_resource();
        mr->deallocate(p, bytes, alignment);
        used_ -= bytes;
    };

    virtual bool do_is_equal(
        const nf9_std_pmr::memory_resource &other) const
        noexcept override
    {
        if (auto *obj = dynamic_cast<const umap_resource *>(&other)) {
            if (max_size_ == obj->max_size_ && used_ == obj->used_)
                return true;
            return false;
        }
        return false;
    };

    size_t get_memory_usage() const
    {
        return used_;
    }

    void set_max_memory_usage(size_t max_mem)
    {
        max_size_ = max_mem;
    }

private:
    /* Max memory allocation in bytes */
    size_t max_size_;

    /* Counter of bytes alocated in templates unordered_map */
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

struct nf9_state
{
    int flags;
    nf9_stats stats;
    uint32_t template_expire_time = TEMPLATE_EXPIRE_TIME;
    std::unique_ptr<umap_resource> limited_mr;

    nf9_std_pmr::unordered_map<stream_id, data_template> templates;
    nf9_std_pmr::unordered_map<device_id, device_options> options;
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
