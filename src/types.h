#ifndef TYPES_H
#define TYPES_H

#include <netflow9.h>
#include <netinet/in.h>
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

struct nf9_state
{
    int flags;
    nf9_stats stats;
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
private:
    uint16_t netflow_version_;
    uint16_t record_count_;
    uint32_t system_uptime_;
    uint32_t epoch_time_;
    uint32_t sequence_number_;
    uint32_t source_id_;

public:
    bool is_well_formed() const
    {
        return ntohs(netflow_version_) == 9;
    }

    uint32_t epoch_time() const
    {
        return ntohl(epoch_time_);
    }

    uint32_t system_uptime() const
    {
        return ntohl(system_uptime_);
    }

    uint32_t source_id() const
    {
        return ntohl(source_id_);
    }

    uint16_t record_count() const
    {
        return ntohs(record_count_);
    }

    uint32_t sequence_number() const
    {
        return ntohl(sequence_number_);
    }
};

/**
 *  Record types as defined by the RFC.
 */
enum class netflow_record_type { TEMPLATE, OPTIONS, DATA };

/**
 *  Not defined in the RFC, but it appears at the start of every record and
 *  serves well as an implementation help.
 *
 *  The structure represents the binary layout of a Netflow9 flowset header.
 *
 *  It's meant to provide portable means of access to Netflow packets in the
 *  receive buffer via pointers and references and as such can't be
 *  instantiated.
 */
struct flowset_header
{
private:
    uint16_t flowset_id_;
    uint16_t length_;

public:
    uint16_t flowset_id() const
    {
        return ntohs(flowset_id_);
    }

    uint16_t length() const
    {
        return ntohs(length_);
    }

    netflow_record_type record_type() const
    {
        if (flowset_id() > 255)
            return netflow_record_type::DATA;
        else if (flowset_id() == 1)
            return netflow_record_type::OPTIONS;
        return netflow_record_type::TEMPLATE;
    }
};

/**
 *  A structure representing the binary layout of a Netflow9 packet.
 *
 *  It's meant to provide portable means of access to Netflow packets in the
 *  receive buffer via pointers and references and as such can't be
 *  instantiated.
 */
struct netflow_packet
{
    netflow_header header_;
    const uint8_t *payload_;

    /**
     *  Returns a reference to the Netflow packet header.
     */
    const netflow_header &header() const
    {
        return header_;
    }

    const uint8_t *get_payload() const
    {
        return payload_;
    }
};

#endif
