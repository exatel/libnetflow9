#include <cstring>
#include "parse.h"

struct flowset_header
{
    uint16_t flowset_id;
    uint16_t length;
};

static nf9_flowset_type get_flowset_type(const flowset_header* header)
{
    uint16_t id = ntohs(header->flowset_id);

    if (id > 255)
        return NF9_FLOWSET_DATA;
    else if (id == 1)
        return NF9_FLOWSET_OPTIONS;
    return NF9_FLOWSET_TEMPLATE;
}

static bool parse_header(const uint8_t** buf, size_t* len, netflow_header* hdr)
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

static bool parse_data_template(const uint8_t** buf, size_t* len,
                                data_template& result)
{
    if (*len < 2 * sizeof(uint16_t))
        return false;

    uint16_t type;
    uint16_t length;

    memcpy(&type, *buf, sizeof(uint16_t));
    *buf += sizeof(uint16_t);
    memcpy(&length, *buf, sizeof(uint16_t));
    *buf += sizeof(uint16_t);
    *len -= 2 * sizeof(uint16_t);

    type = ntohs(type);
    length = ntohs(length);

    result.fields.emplace_back(type, length);
    result.total_length += length;

    return true;
}

static bool parse_data_template_flowset(const uint8_t* buf, size_t len,
                                        nf9_state* state,
                                        nf9_parse_result* result)
{
    if (len < 2 * sizeof(uint16_t))
        return false;

    uint16_t template_id;
    uint16_t field_count;

    memcpy(&template_id, buf, sizeof(uint16_t));
    buf += sizeof(uint16_t);
    memcpy(&field_count, buf, sizeof(uint16_t));
    buf += sizeof(uint16_t);
    len -= 2 * sizeof(uint16_t);

    template_id = ntohs(template_id);
    field_count = ntohs(field_count);

    result->flowsets.push_back(flowset{NF9_FLOWSET_TEMPLATE});
    flowset& f = result->flowsets.back();
    data_template& tmpl = f.dtemplate;

    while (field_count-- > 0 && len > 0) {
        if (!parse_data_template(&buf, &len, tmpl))
            return false;
    }

    state->templates[template_id] = tmpl;

    return true;
}

static bool parse_flow(const uint8_t** buf, size_t* len, data_template& tmpl,
                       flowset& result)
{
    if (tmpl.fields.empty()) {
        *buf += *len;
        *len = 0;
        return true;
    }

    if (tmpl.total_length > *len) {
        *buf += *len;
        *len = 0;
        return true;
    }

    result.flows.emplace_back();
    flow& f = result.flows.back();

    for (const template_field& tf : tmpl.fields) {
        int type = tf.first;
        size_t field_length = tf.second;

        if (field_length > *len)
            return false;

        if (field_length == 0)
            break;

        std::vector<uint8_t> field_value;
        field_value.assign(*buf, *buf + field_length);

        *buf += field_length;
        *len -= field_length;

        f[type] = field_value;
    }

    return true;
}

static bool parse_data_flowset(const uint8_t* buf, size_t len, nf9_state* state,
                               uint16_t template_id, nf9_parse_result* result)
{
    result->flowsets.push_back(flowset{NF9_FLOWSET_DATA});

    if (state->templates.count(template_id) == 0) {
        state->stats.missing_template_errors++;
        return true;
    }

    flowset& fset = result->flowsets.back();
    data_template& tmpl = state->templates[template_id];

    while (len > 0) {
        if (!parse_flow(&buf, &len, tmpl, fset))
            return false;
    }

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

    size_t flowset_length = ntohs(header.length);

    // The length must be at least 4 because each flowset has at
    // least two uint16_t fields: flowset_id and the length field
    // itself.
    if (flowset_length < 2 * sizeof(uint16_t))
        return false;

    flowset_length -= 2 * sizeof(uint16_t);
    if (flowset_length > *len)
        return false;

    switch (get_flowset_type(&header)) {
        case NF9_FLOWSET_TEMPLATE: {
            state->stats.templates++;
            if (!parse_data_template_flowset(*buf, *len, state, result))
                return false;
            break;
        }
        case NF9_FLOWSET_OPTIONS:
            state->stats.option_templates++;
            result->flowsets.push_back(flowset{NF9_FLOWSET_OPTIONS});
            break;
        case NF9_FLOWSET_DATA:
            state->stats.records++;
            if (!parse_data_flowset(*buf, *len, state, ntohs(header.flowset_id),
                                    result))
                return false;
            break;
        default:
            state->stats.malformed_packets++;
            return false;
    }
    *buf += flowset_length;
    *len -= flowset_length;

    return true;
}

bool parse(const uint8_t* buf, size_t len, nf9_state* state,
           nf9_parse_result* result)
{
    netflow_header header;

    if (!parse_header(&buf, &len, &header))
        return false;

    size_t num_flowsets = ntohs(header.count);
    for (size_t i = 0; i < num_flowsets && len > 0; i++) {
        if (!parse_flowset(&buf, &len, result, state))
            return false;
    }

    return true;
}
