#include "parse.h"
#include <cassert>
#include <cstring>

struct flowset_header
{
    uint16_t flowset_id;
    uint16_t length;
};

// Cursor for a byte buffer.  Allows safely retrieving values from the
// underlying buffer.
struct buffer
{
    const uint8_t* const buf;
    const size_t len;
    const uint8_t* ptr;

    // How many bytes do we have left?
    size_t remaining() const
    {
        assert(ptr >= buf && size_t(ptr - buf) <= len);
        return len - (ptr - buf);
    }

    bool get(void* dst, size_t size)
    {
        if (remaining() < size)
            return false;

        memcpy(dst, ptr, size);
        advance(size);
        return true;
    }

    void advance(size_t n)
    {
        assert(n <= remaining());
        ptr += n;
    }
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

static bool parse_header(buffer& buf, netflow_header* hdr)
{
    if (!buf.get(hdr, sizeof(*hdr)))
        return false;

    if (ntohs(hdr->version) != 9)
        return false;

    return true;
}

static bool parse_data_template(buffer& buf, data_template& result)
{
    uint16_t type;
    uint16_t length;

    if (!buf.get(&type, sizeof(type)))
        return false;

    if (!buf.get(&length, sizeof(length)))
        return false;

    type = ntohs(type);
    length = ntohs(length);

    result.fields.emplace_back(type, length);
    result.total_length += length;

    return true;
}

static bool parse_data_template_flowset(buffer& buf, nf9_state* state,
                                        nf9_parse_result* result)
{
    uint16_t template_id;
    uint16_t field_count;

    if (!buf.get(&template_id, sizeof(template_id)))
        return false;
    if (!buf.get(&field_count, sizeof(field_count)))
        return false;

    template_id = ntohs(template_id);
    field_count = ntohs(field_count);

    result->flowsets.push_back(flowset{NF9_FLOWSET_TEMPLATE});
    flowset& f = result->flowsets.back();
    data_template& tmpl = f.dtemplate;

    while (field_count-- > 0 && buf.remaining() > 0) {
        if (!parse_data_template(buf, tmpl))
            return false;
    }

    state->templates[template_id] = tmpl;

    return true;
}

static bool parse_flow(buffer& buf, data_template& tmpl, flowset& result)
{
    if (tmpl.fields.empty()) {
        buf.advance(buf.remaining());
        return true;
    }

    if (tmpl.total_length > buf.remaining()) {
        buf.advance(buf.remaining());
        return true;
    }

    result.flows.emplace_back();
    flow& f = result.flows.back();

    for (const template_field& tf : tmpl.fields) {
        int type = tf.first;
        size_t field_length = tf.second;

        if (field_length > buf.remaining())
            return false;

        if (field_length == 0)
            break;

        std::vector<uint8_t> field_value;
        field_value.assign(field_length, 0);
        buf.get(field_value.data(), field_length);

        f[type] = field_value;
    }

    return true;
}

static bool parse_data_flowset(buffer& buf, nf9_state* state,
                               uint16_t template_id, nf9_parse_result* result)
{
    result->flowsets.push_back(flowset{NF9_FLOWSET_DATA});

    if (state->templates.count(template_id) == 0) {
        state->stats.missing_template_errors++;
        buf.advance(buf.remaining());
        return true;
    }

    flowset& fset = result->flowsets.back();
    data_template& tmpl = state->templates[template_id];

    while (buf.remaining() > 0) {
        if (!parse_flow(buf, tmpl, fset))
            return false;
    }

    return true;
}

static bool parse_flowset(buffer& buf, nf9_parse_result* result,
                          nf9_state* state)
{
    flowset_header header;

    if (!buf.get(&header, sizeof(header)))
        return false;

    size_t flowset_length = ntohs(header.length);

    // The length must be at least 4 because each flowset has at
    // least two uint16_t fields: flowset_id and the length field
    // itself.
    if (flowset_length < sizeof(header))
        return false;

    flowset_length -= sizeof(header);
    if (flowset_length > buf.remaining())
        return false;

    buffer tmpbuf{buf.ptr, flowset_length, buf.ptr};
    buf.advance(flowset_length);

    switch (get_flowset_type(&header)) {
        case NF9_FLOWSET_TEMPLATE:
            state->stats.templates++;
            return parse_data_template_flowset(tmpbuf, state, result);

        case NF9_FLOWSET_OPTIONS:
            state->stats.option_templates++;
            result->flowsets.push_back(flowset{NF9_FLOWSET_OPTIONS});
            return true;
        case NF9_FLOWSET_DATA:
            state->stats.records++;
            return parse_data_flowset(tmpbuf, state, ntohs(header.flowset_id),
                                      result);
        default:
            state->stats.malformed_packets++;
            return false;
    }

    // Unreachable
    assert(0);
}

bool parse(const uint8_t* data, size_t len, nf9_state* state,
           nf9_parse_result* result)
{
    buffer buf{data, len, data};
    netflow_header header;

    if (!parse_header(buf, &header))
        return false;

    size_t num_flowsets = ntohs(header.count);
    for (size_t i = 0; i < num_flowsets && buf.remaining() > 0; i++) {
        if (!parse_flowset(buf, result, state))
            return false;
    }

    return true;
}
