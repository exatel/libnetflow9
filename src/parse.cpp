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

static bool parse_header(netflow_header* hdr, const uint8_t* buf, size_t len)
{
    if (len < sizeof(netflow_header))
        return false;
    memcpy(hdr, buf, sizeof(netflow_header));

    if (ntohs(hdr->version) != 9)
        return false;

    return true;
}

static bool parse_flowsets(size_t count, nf9_state* state, const uint8_t* buf,
                           size_t len, nf9_parse_result* result)
{
    const uint8_t* end = buf + len;
    buf += sizeof(netflow_header);
    uint16_t i = 0;
    while (buf <= end - sizeof(flowset_header) && i < count) {
        struct flowset_header flowset_info = {};
        memcpy(&flowset_info, buf, sizeof(flowset_header));

        size_t flowset_length = ntohs(flowset_info.length);

        // The length must be at least 4 because each flowset has at
        // least two uint16_t fields: flowset_id and the length field
        // itself.
        if (flowset_length < 4)
            return false;

        switch (get_flowset_type(&flowset_info)) {
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
                break;
        }

        buf += flowset_length;
        ++i;
    }
    if (buf > end)
        return false;
    return true;
}

bool parse(nf9_state* state, const uint8_t* buf, size_t len,
           nf9_parse_result* result)
{
    netflow_header hdr;

    if (!parse_header(&hdr, buf, len))
        return false;

    size_t num_flowsets = ntohs(hdr.count);
    if (!parse_flowsets(num_flowsets, state, buf, len, result))
        return false;

    return true;
}
