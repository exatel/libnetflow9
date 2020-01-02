#include <cstring>
#include "parse.h"

static nf9_flowset_type get_flowset_type(const flowset_header* header)
{
    uint16_t id = ntohs(header->flowset_id);

    if (id > 255)
        return NF9_FLOWSET_DATA;
    else if (id == 1)
        return NF9_FLOWSET_OPTIONS;
    return NF9_FLOWSET_TEMPLATE;
}

static bool parse_header(netflow_header* hdr, const uint8_t** buf, size_t* len)
{
    if (*len < sizeof(netflow_header))
        return false;
    memcpy(hdr, *buf, sizeof(netflow_header));

    *buf += sizeof(netflow_header);
    *len -= sizeof(netflow_header);

    if (ntohs(hdr->version) != 9)
        return false;

    return true;
}

static bool parse_flowset(const uint8_t** buf, size_t* len,
                          nf9_parse_result* result, nf9_state* state)
{
    if (*len < sizeof(flowset_header))
        return false;

    flowset_header header;
    memcpy(&header, *buf, sizeof(flowset_header));

    *buf += sizeof(flowset_header);
    *len -= sizeof(flowset_header);

    uint16_t flowset_length = ntohs(header.length);

    // The length must be at least 4 because each flowset has at
    // least two uint16_t fields: flowset_id and the length field
    // itself.
    if (flowset_length < 2 * sizeof(uint16_t))
        return false;

    flowset_length -= 2 * sizeof(uint16_t);
    if (flowset_length > *len)
        return false;

    switch (get_flowset_type(&header)) {
        case NF9_FLOWSET_TEMPLATE:
            state->stats.templates++;
            result->flowsets.push_back(flowset{NF9_FLOWSET_TEMPLATE});
            break;
        case NF9_FLOWSET_OPTIONS:
            state->stats.option_templates++;
            result->flowsets.push_back(flowset{NF9_FLOWSET_OPTIONS});
            break;
        case NF9_FLOWSET_DATA:
            state->stats.records++;
            result->flowsets.push_back(flowset{NF9_FLOWSET_DATA});
            break;
        default:
            state->stats.malformed_packets++;
            return false;
    }

    *buf += flowset_length;
    *len -= flowset_length;

    return true;
}

bool parse(nf9_state* state, const uint8_t* buf, size_t len,
           nf9_parse_result* result)
{
    netflow_header header;

    if (!parse_header(&header, &buf, &len))
        return false;

    size_t num_flowsets = ntohs(header.count);
    for (size_t i = 0; i < num_flowsets && len > 0; i++) {
        if (!parse_flowset(&buf, &len, result, state))
            return false;
    }

    return true;
}
