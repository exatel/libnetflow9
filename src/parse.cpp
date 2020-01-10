#include "parse.h"
#include <cassert>
#include <cstring>

struct flowset_header
{
    uint16_t flowset_id;
    uint16_t length;
};

struct data_template_header
{
    uint16_t template_id;
    uint16_t field_count;
};

struct option_template_header
{
    uint16_t template_id;
    uint16_t option_scope_length;
    uint16_t option_length;
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

static nf9_flowset_type get_flowset_type(const flowset_header& header)
{
    uint16_t id = ntohs(header.flowset_id);

    if (id > 255)
        return NF9_FLOWSET_DATA;
    else if (id == 1)
        return NF9_FLOWSET_OPTIONS;
    return NF9_FLOWSET_TEMPLATE;
}

static bool parse_header(buffer& buf, netflow_header& hdr)
{
    if (!buf.get(&hdr, sizeof(hdr)))
        return false;

    if (ntohs(hdr.version) != 9)
        return false;

    return true;
}

static bool parse_template_field(buffer& buf, uint16_t& type, uint16_t& length)
{
    if (!buf.get(&type, sizeof(type)))
        return false;

    if (!buf.get(&length, sizeof(length)))
        return false;

    type = ntohs(type);
    length = ntohs(length);

    if (length == 0)
        return false;
    return true;
}

static bool parse_data_template(buffer& buf, data_template& result)
{
    uint16_t type;
    uint16_t length;

    if (!parse_template_field(buf, type, length))
        return false;

    result.fields.emplace_back(type, length);
    result.total_length += length;

    return true;
}

static bool parse_data_template_flowset(buffer& buf, nf9_state& state,
                                        const nf9_addr& addr,
                                        uint32_t source_id,
                                        nf9_parse_result& result)
{
    while (buf.remaining() > 0) {
        data_template_header header;
        if (!buf.get(&header, sizeof(header)))
            return false;

        flowset& f = result.flowsets.emplace_back(flowset{});
        f.type = NF9_FLOWSET_TEMPLATE;
        data_template& tmpl = f.dtemplate;
        uint16_t field_count = ntohs(header.field_count);

        while (field_count-- > 0 && buf.remaining() > 0) {
            if (!parse_data_template(buf, tmpl))
                return false;
        }

        if (tmpl.total_length == 0)
            return false;

        exporter_stream_id stream_id = {addr, source_id,
                                        ntohs(header.template_id)};
        state.templates[stream_id] = tmpl;
    }
    return true;
}

static bool parse_option_template(buffer& buf, data_template& result,
                                  uint16_t option_scope_length,
                                  uint16_t option_length)
{
    uint16_t type;
    uint16_t length;

    while (option_scope_length && buf.remaining() > 0) {
        if (!parse_template_field(buf, type, length))
            return false;
        if (length == 0)
            return false;

        nf9_field field_type = NF9_SCOPE_FIELD(type);
        result.fields.emplace_back(field_type, length);
        result.total_length += length;
        if (option_scope_length < sizeof(type) + sizeof(length))
            return false;
        option_scope_length -= sizeof(type) + sizeof(length);
    }

    while (option_length && buf.remaining() > 0) {
        if (!parse_template_field(buf, type, length))
            return false;
        if (length == 0)
            return false;

        nf9_field field_type = NF9_DATA_FIELD(type);
        result.fields.emplace_back(field_type, length);
        result.total_length += length;
        if (option_length < sizeof(type) + sizeof(length))
            return false;
        option_length -= sizeof(type) + sizeof(length);
    }

    return true;
}

static bool parse_option_template_flowset(buffer& buf, nf9_state& state,
                                          const nf9_addr& addr,
                                          uint32_t source_id,
                                          nf9_parse_result& result)
{
    // TODO: Consider parsing flowsets with multiple option templates
    option_template_header header;
    if (!buf.get(&header, sizeof(header)))
        return false;

    flowset& f = result.flowsets.emplace_back(flowset{});
    f.type = NF9_FLOWSET_OPTIONS;
    data_template& tmpl = f.dtemplate;

    if (!parse_option_template(buf, tmpl, ntohs(header.option_scope_length),
                               ntohs(header.option_length)))
        return false;

    if (tmpl.total_length == 0)
        return false;

    exporter_stream_id stream_id = {addr, source_id, ntohs(header.template_id)};
    state.templates[stream_id] = tmpl;

    // omit padding bytes
    buf.advance(buf.remaining());
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
        uint32_t type = tf.first;
        size_t field_length = tf.second;

        if (field_length > buf.remaining())
            return false;

        if (field_length == 0)
            break;

        std::vector<uint8_t> field_value(field_length, 0);
        buf.get(field_value.data(), field_length);

        f[type] = field_value;
    }

    return true;
}

static bool parse_data_flowset(buffer& buf, nf9_state& state,
                               uint16_t flowset_id, const nf9_addr& srcaddr,
                               uint32_t source_id, nf9_parse_result& result)
{
    exporter_stream_id stream_id = {srcaddr, source_id, flowset_id};

    flowset& f = result.flowsets.emplace_back(flowset{});
    f.type = NF9_FLOWSET_DATA;

    if (state.templates.count(stream_id) == 0) {
        state.stats.missing_template_errors++;
        buf.advance(buf.remaining());
        return true;
    }

    data_template& tmpl = state.templates[stream_id];
    while (buf.remaining() > 0) {
        if (!parse_flow(buf, tmpl, f))
            return false;
    }

    return true;
}

static bool parse_flowset(buffer& buf, uint32_t source_id,
                          const nf9_addr& srcaddr, nf9_parse_result& result,
                          nf9_state& state)
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

    switch (get_flowset_type(header)) {
        case NF9_FLOWSET_TEMPLATE:
            state.stats.templates++;
            return parse_data_template_flowset(tmpbuf, state, srcaddr,
                                               source_id, result);

        case NF9_FLOWSET_OPTIONS:
            state.stats.option_templates++;
            return parse_option_template_flowset(tmpbuf, state, srcaddr,
                                                 source_id, result);
            return true;

        case NF9_FLOWSET_DATA:
            state.stats.records++;
            return parse_data_flowset(tmpbuf, state, ntohs(header.flowset_id),
                                      srcaddr, source_id, result);
        default:
            state.stats.malformed_packets++;
            return false;
    }

    // Unreachable
    assert(0);
}

bool parse(const uint8_t* data, size_t len, const nf9_addr& srcaddr,
           nf9_state* state, nf9_parse_result* result)
{
    buffer buf{data, len, data};
    netflow_header header;

    if (!parse_header(buf, header))
        return false;

    size_t num_flowsets = ntohs(header.count);
    for (size_t i = 0; i < num_flowsets && buf.remaining() > 0; i++) {
        if (!parse_flowset(buf, ntohl(header.source_id), srcaddr, *result,
                           *state))
            return false;
    }

    return true;
}
