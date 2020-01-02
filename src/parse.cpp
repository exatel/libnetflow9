#include <cstring>
#include "parse.h"

static nf9_rc parse_header(const uint8_t* buf, size_t len,
                           netflow_packet* packet)
{
    if (len < sizeof(netflow_header))
        return nf9_rc::RESULT_ERR;
    memcpy(packet, buf, sizeof(netflow_header));
    packet->payload_ = buf + sizeof(netflow_header);

    return packet->header().is_well_formed() ? nf9_rc::RESULT_OK
                                             : nf9_rc::RESULT_ERR;
}

static nf9_rc parse_flowsets(nf9_state* state, const uint8_t* buf, size_t len,
                             netflow_packet* packet, nf9_parse_result* result)
{
    const uint8_t* end = buf + len;
    buf += sizeof(netflow_header);
    uint16_t i = 0;
    while (buf <= end - sizeof(flowset_header) &&
           i < packet->header().record_count()) {
        struct flowset_header flowset_info = {};
        memcpy(&flowset_info, buf, sizeof(flowset_header));

        // The length must be at least 4 because each flowset has at
        // least two uint16_t fields: flowset_id and the length field
        // itself.
        if (flowset_info.length() < 4)
            return nf9_rc::RESULT_ERR;

        switch (flowset_info.record_type()) {
            case netflow_record_type::TEMPLATE:
                state->stats.templates++;
                result->flowsets.push_back(flowset{NF9_FLOWSET_TEMPLATE});
                break;
            case netflow_record_type::OPTIONS:
                state->stats.option_templates++;
                result->flowsets.push_back(flowset{NF9_FLOWSET_OPTIONS});
                break;
            case netflow_record_type::DATA:
                state->stats.records++;
                result->flowsets.push_back(flowset{NF9_FLOWSET_DATA});
                break;
            default:
                break;
        }

        buf += flowset_info.length();
        ++i;
    }
    if (buf > end)
        return nf9_rc::RESULT_ERR;
    return nf9_rc::RESULT_OK;
}

nf9_rc parse(nf9_state* state, const uint8_t* buf, size_t len,
             nf9_parse_result* result)
{
    netflow_packet packet = {};

    if (nf9_rc::RESULT_OK != parse_header(buf, len, &packet))
        return nf9_rc::RESULT_ERR;

    if (nf9_rc::RESULT_OK != parse_flowsets(state, buf, len, &packet, result))
        return nf9_rc::RESULT_ERR;

    return nf9_rc::RESULT_OK;
}
