/*
 * Copyright © 2019-2020 Exatel S.A.
 * Contact: opensource@exatel.pl
 * LICENSE: LGPL-3.0-or-later, See COPYING*.md files.
 */

#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netflow9.h>
#include <netinet/in.h>
#include <tins/tins.h>
#include <ctime>
#include <functional>
#include <stdexcept>
#include <string>
#include <variant>
#include "types.h"

struct pcap_packet
{
    std::vector<uint8_t> data_ = {};
    nf9_addr addr;
};

// Get packets from file.
std::vector<pcap_packet> get_packets(const char *pcap_path);

// Create a IPv4 nf9_addr from a string of the form "a.b.c.d".
nf9_addr make_inet_addr(const char *addr, uint16_t port = 0);

// Create a IPv6 nf9_addr from a string.
nf9_addr make_inet6_addr(const char *addr, uint16_t port = 0);

// Convert a binary address to string.
std::string address_to_string(const nf9_addr &addr);

struct packet_deleter
{
    void operator()(nf9_packet *result)
    {
        nf9_free_packet(result);
    }
};

struct stats_deleter
{
    void operator()(const nf9_stats *stats)
    {
        nf9_free_stats(stats);
    }
};

using packet = std::unique_ptr<nf9_packet, packet_deleter>;
using stats = std::unique_ptr<const nf9_stats, stats_deleter>;

class test : public ::testing::Test
{
protected:
    void SetUp() override
    {
        state_ = nf9_init(NF9_STORE_SAMPLING_RATES);
    }

    void TearDown() override
    {
        nf9_free(state_);
    }

    stats get_stats()
    {
        return stats(nf9_get_stats(state_));
    }

    packet decode(const uint8_t *buf, size_t len, const nf9_addr *addr)
    {
        nf9_packet *pkt;
        if (nf9_decode(state_, &pkt, buf, len, addr))
            return packet(nullptr);
        return packet(pkt);
    }

    nf9_state *state_;
};

// Objects of this class can build NetFlow9 packets for unit tests.
class netflow_packet_builder
{
public:
    netflow_packet_builder() : timestamp_(time(nullptr))
    {
    }

    // Set the NetFlow version in header (default 9).
    netflow_packet_builder &set_netflow_version(uint16_t version)
    {
        version_ = version;
        return *this;
    }

    // Set the system uptime in header (default 0).
    netflow_packet_builder &set_system_uptime(uint32_t uptime)
    {
        uptime_ = uptime;
        return *this;
    }

    // Set the unix timestamp in header (default now).
    netflow_packet_builder &set_unix_timestamp(uint32_t timestamp)
    {
        timestamp_ = timestamp;
        return *this;
    }

    // Set the sequence number in header (default 0).
    netflow_packet_builder &set_sequence_number(uint32_t sequence)
    {
        sequence_ = sequence;
        return *this;
    }

    // Set the source_id in header (default 0).
    netflow_packet_builder &set_source_id(uint32_t source_id)
    {
        source_id_ = source_id;
        return *this;
    }

    // Begin a new template flowset with given id.
    netflow_packet_builder &add_data_template_flowset(uint16_t flowset_id)
    {
        if (flowset_id > 255)
            throw std::invalid_argument("flowset_id must be <= 255");
        records_.push_back(data_template_flowset{flowset_id, {}});
        return *this;
    }

    // Begin a new data template in last flowset.  Fails if
    // ``add_data_template_flowset`` was not yet called.
    netflow_packet_builder &add_data_template(uint16_t template_id)
    {
        if (template_id <= 255)
            throw std::invalid_argument("template_id must be > 255");
        if (records_.empty())
            throw std::runtime_error("no flowsets");

        data_template_flowset &flowset = last_data_template_flowset();
        flowset.templates.push_back(data_template{template_id, {}});
        return *this;
    }

    // Add a field to the latest data template.  Fails if
    // ``add_data_template`` was not yet called.
    netflow_packet_builder &add_data_template_field(uint16_t type,
                                                    uint16_t length)
    {
        if (records_.empty())
            throw std::runtime_error("no flowsets");
        if (last_data_template_flowset().templates.empty())
            throw std::runtime_error("no templates in last flowset");

        data_template &tmpl = last_data_template_flowset().templates.back();
        tmpl.fields.push_back({type, length});
        return *this;
    }

    // Begin a new data flowset with given id.
    netflow_packet_builder &add_data_flowset(uint16_t flowset_id)
    {
        records_.push_back(data_flowset{flowset_id, {}});
        return *this;
    }

    // Add a field to latest data flowset.  Fails if
    // ``add_data_flowset`` was not yet called.
    template <typename T>
    netflow_packet_builder &add_data_field(T value)
    {
        if (records_.empty())
            throw std::runtime_error("no flowsets");

        bytes value_bytes = to_bytes(value);
        last_data_flowset().values.emplace_back(value_bytes);
        return *this;
    }

    // Begin a new option template with given id.
    netflow_packet_builder &add_option_template_flowset(uint16_t template_id)
    {
        if (template_id <= 255)
            throw std::invalid_argument("template_id must be > 255");

        records_.push_back(option_template_flowset{template_id, {}, {}});
        return *this;
    }

    // Add a scope field to the latest option template.  Fails if
    // ``add_option_template_flowset`` was not yet called.
    netflow_packet_builder &add_option_scope_field(uint16_t type,
                                                   uint16_t length)
    {
        if (type == 0 || type > 5)
            throw std::invalid_argument(
                "scope field type must be > 0 and <= 5");

        option_template_flowset &tmpl = last_option_template_flowset();
        tmpl.scope_fields.push_back({type, length});
        return *this;
    }

    // Add a field to the latest data template.  Fails if
    // ``add_data_template`` was not yet called.
    netflow_packet_builder &add_option_field(uint16_t type, uint16_t length)
    {
        option_template_flowset &tmpl = last_option_template_flowset();
        tmpl.fields.push_back({type, length});
        return *this;
    }

    // Build the entire packet.
    std::vector<uint8_t> build() const
    {
        bytes header = build_header();
        bytes records = build_records();
        auto packet = header + records;
        return {packet.begin(), packet.end()};
    }

private:
    using bytes = std::basic_string<uint8_t>;
    using field_def =
        std::pair<uint16_t, uint16_t>;  // Field type, field length

    struct data_template
    {
        uint16_t template_id;
        std::vector<field_def> fields;
    };

    struct option_template_flowset
    {
        uint16_t template_id;
        std::vector<field_def> scope_fields;
        std::vector<field_def> fields;
    };

    struct data_template_flowset
    {
        uint16_t flowset_id;
        std::vector<data_template> templates;
    };

    struct data_flowset
    {
        uint16_t flowset_id;  // = template_id
        std::vector<bytes> values;
    };

    using record = std::variant<data_template_flowset, data_flowset,
                                option_template_flowset>;

    bytes build_header() const
    {
        netflow_header hd;
        hd.version = htons(version_);
        hd.count = htons(records_.size());
        hd.uptime = htonl(uptime_);
        hd.timestamp = htonl(timestamp_);
        hd.sequence = htonl(sequence_);
        hd.source_id = htonl(source_id_);
        return bytes(reinterpret_cast<const uint8_t *>(&hd),
                     reinterpret_cast<const uint8_t *>(&hd) + sizeof(hd));
    }

    bytes build_records() const
    {
        bytes ret;
        for (const record &rec : records_) {
            if (rec.index() == 0)
                ret += build_data_template_flowset(
                    std::get<data_template_flowset>(rec));
            else if (rec.index() == 1)
                ret += build_data_flowset(std::get<data_flowset>(rec));
            else if (rec.index() == 2)
                ret += build_option_template_flowset(
                    std::get<option_template_flowset>(rec));
        }

        return ret;
    }

    bytes build_data_template_flowset(const data_template_flowset &tf) const
    {
        bytes template_bytes;
        for (const data_template &t : tf.templates)
            template_bytes += build_data_template(t);

        return to_bytes(htons(tf.flowset_id)) +  // flowset_id
               to_bytes(htons(
                   sizeof(uint16_t) * 2 +
                   template_bytes.size())) +  // flowset length in
                                              // bytes (including two 2-byte
                                              // fields at beginning)
               template_bytes;
    }

    bytes build_data_flowset(const data_flowset &df) const
    {
        bytes body;
        for (const bytes &value : df.values)
            body += value;

        bytes padding_bytes = padding(2 * sizeof(uint16_t) + body.size());

        return to_bytes(htons(df.flowset_id)) +
               to_bytes(htons(sizeof(uint16_t) * 2 + body.size() +
                              padding_bytes.size())) +
               body + padding_bytes;
    }

    bytes build_data_template(const data_template &t) const
    {
        bytes ret;
        ret += to_bytes(htons(t.template_id));
        ret += to_bytes(htons(t.fields.size()));
        for (const auto &fd : t.fields) {
            ret += to_bytes(htons(fd.first));
            ret += to_bytes(htons(fd.second));
        }

        return ret;
    }

    bytes build_option_template_flowset(const option_template_flowset &t) const
    {
        bytes scope;
        bytes option;

        for (const field_def &fd : t.scope_fields) {
            scope += to_bytes(htons(fd.first));
            scope += to_bytes(htons(fd.second));
        }
        for (const field_def &fd : t.fields) {
            option += to_bytes(htons(fd.first));
            option += to_bytes(htons(fd.second));
        }

        bytes padding_bytes =
            padding(5 * sizeof(uint16_t) + scope.size() + option.size());

        return to_bytes(htons(1))  // flowset_id = 1 for all option templates
               + to_bytes(htons(5 * sizeof(uint16_t) + scope.size() +
                                option.size() + padding_bytes.size())) +
               to_bytes(htons(t.template_id)) + to_bytes(htons(scope.size())) +
               to_bytes(htons(option.size())) + scope + option + padding_bytes;
    }

    // Convert any integer value to bytes.
    template <typename T>
    static bytes to_bytes(T t)
    {
        union {
            T value;
            uint8_t bytes[sizeof(T)];
        } u;
        u.value = t;
        return bytes(u.bytes, u.bytes + sizeof(T));
    }

    static bytes padding(size_t record_size)
    {
        if (record_size % sizeof(uint32_t) == 0)
            return bytes();

        size_t padding = sizeof(uint32_t) - (record_size % sizeof(uint32_t));
        return bytes(padding, 0x0);
    }

    data_template_flowset &last_data_template_flowset()
    {
        return std::get<data_template_flowset>(records_.back());
    }

    data_flowset &last_data_flowset()
    {
        return std::get<data_flowset>(records_.back());
    }

    option_template_flowset &last_option_template_flowset()
    {
        return std::get<option_template_flowset>(records_.back());
    }

    uint16_t version_ = 9;
    uint32_t uptime_ = 0;
    uint32_t timestamp_;
    uint32_t sequence_ = 0;
    uint32_t source_id_ = 0;
    std::vector<record> records_;
};

#endif
