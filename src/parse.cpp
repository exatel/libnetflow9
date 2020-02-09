/*
 * Copyright © 2019-2020 Exatel S.A.
 * Contact: github@exatel.pl
 * LICENSE: LGPL-3.0-or-later, See COPYING*.md files.
 */

#include "parse.h"
#include <cassert>
#include <cstring>
#include "storage.h"

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

struct parsing_context
{
    buffer& buf;
    uint32_t source_id;
    const nf9_addr& srcaddr;
    nf9_parse_result& result;
    nf9_state& state;
};

/*
 * The FlowSet ID is used to distinguish template records from data records.
 * FlowSet IDs in the range of 0-255 are reserved for template records.
 * Currently, the template record that describes data fields has a FlowSet ID
 * of zero and the template record that describes option fields has a FlowSet
 * ID of 1. For this reason flowsets with Flowset IDs in the range of 2-255 are
 * treated as invalid. A data record always has a nonzero FlowSet ID greater
 * than 255.
 */
static nf9_flowset_type get_flowset_type(const uint16_t flowset_id)
{
    if (flowset_id > 255)
        return NF9_FLOWSET_DATA;
    else if (flowset_id == 0)
        return NF9_FLOWSET_TEMPLATE;
    else if (flowset_id == 1)
        return NF9_FLOWSET_OPTIONS;
    else
        return static_cast<nf9_flowset_type>(-1);
}

static bool parse_header(buffer& buf, netflow_header& hdr, uint32_t& timestamp,
                         uint32_t& uptime)
{
    if (!buf.get(&hdr, sizeof(hdr)))
        return false;

    if (ntohs(hdr.version) != 9)
        return false;

    timestamp = ntohl(hdr.timestamp);
    uptime = ntohl(hdr.uptime);

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

static bool parse_data_template(buffer& buf, data_template& tmpl,
                                nf9_parse_result& result)
{
    uint16_t type;
    uint16_t length;

    if (!parse_template_field(buf, type, length))
        return false;

    tmpl.fields.emplace_back(NF9_DATA_FIELD(type), length);
    tmpl.total_length += length;
    tmpl.timestamp = result.timestamp;
    tmpl.is_option = false;

    return true;
}

static bool parse_data_template_flowset(parsing_context& ctx)
{
    while (ctx.buf.remaining() > 0) {
        data_template_header header;
        if (!ctx.buf.get(&header, sizeof(header)))
            return false;

        flowset f = flowset();
        f.type = NF9_FLOWSET_TEMPLATE;
        data_template& tmpl = f.dtemplate;
        uint16_t field_count = ntohs(header.field_count);

        while (field_count-- > 0 && ctx.buf.remaining() > 0) {
            if (!parse_data_template(ctx.buf, tmpl, ctx.result))
                return false;
        }

        stream_id sid = {device_id{ctx.srcaddr, ctx.source_id},
                         ntohs(header.template_id)};

        if (!save_template(tmpl, sid, ctx.state, ctx.result))
            return false;

        ctx.result.flowsets.emplace_back(std::move(f));
    }
    return true;
}

static bool parse_option_template(buffer& buf, data_template& tmpl,
                                  uint16_t option_scope_length,
                                  uint16_t option_length, uint32_t timestamp)
{
    uint16_t type;
    uint16_t length;

    while (option_scope_length && buf.remaining() > 0) {
        if (!parse_template_field(buf, type, length))
            return false;
        if (length == 0)
            return false;

        nf9_field field_type = NF9_SCOPE_FIELD(type);
        tmpl.fields.emplace_back(field_type, length);
        tmpl.total_length += length;
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
        tmpl.fields.emplace_back(field_type, length);
        tmpl.total_length += length;
        if (option_length < sizeof(type) + sizeof(length))
            return false;
        option_length -= sizeof(type) + sizeof(length);
    }
    tmpl.timestamp = timestamp;
    tmpl.is_option = true;

    return true;
}

static bool parse_option_template_flowset(parsing_context& ctx)
{
    // TODO: Consider parsing flowsets with multiple option templates
    option_template_header header;
    if (!ctx.buf.get(&header, sizeof(header)))
        return false;

    flowset f = flowset();
    f.type = NF9_FLOWSET_OPTIONS;
    data_template& tmpl = f.dtemplate;

    if (!parse_option_template(ctx.buf, tmpl, ntohs(header.option_scope_length),
                               ntohs(header.option_length),
                               ctx.result.timestamp))
        return false;

    stream_id sid = {device_id{ctx.srcaddr, ctx.source_id},
                     ntohs(header.template_id)};

    if (!save_template(tmpl, sid, ctx.state, ctx.result))
        return false;

    ctx.result.flowsets.emplace_back(std::move(f));

    // omit padding bytes
    ctx.buf.advance(ctx.buf.remaining());
    return true;
}

static bool parse_flow(parsing_context& ctx, data_template& tmpl,
                       flowset& result)
{
    if (tmpl.fields.empty()) {
        ctx.buf.advance(ctx.buf.remaining());
        return true;
    }

    if (tmpl.total_length > ctx.buf.remaining()) {
        ctx.buf.advance(ctx.buf.remaining());
        return true;
    }

    flow f = flow();

    for (const template_field& tf : tmpl.fields) {
        uint32_t type = tf.first;
        size_t field_length = tf.second;

        if (field_length > ctx.buf.remaining())
            return false;

        if (field_length == 0)
            break;

        pmr::vector<uint8_t> field_value(field_length, 0);
        ctx.buf.get(field_value.data(), field_length);

        f[type] = field_value;
    }

    if (tmpl.is_option) {
        device_id dev_id = {ctx.srcaddr, ctx.source_id};
        device_options dev_opts = {f, ctx.result.timestamp};
        if (!save_option(ctx.state, dev_id, dev_opts))
            return false;
    }

    result.flows.emplace_back(std::move(f));
    return true;
}

static bool parse_data_flowset(parsing_context& ctx, uint16_t flowset_id)
{
    stream_id sid = {device_id{ctx.srcaddr, ctx.source_id}, flowset_id};

    flowset f = flowset();
    f.type = NF9_FLOWSET_DATA;

    if (ctx.state.templates.count(sid) == 0) {
        ++ctx.state.stats.missing_template_errors;
        ctx.buf.advance(ctx.buf.remaining());
        return true;
    }

    data_template& tmpl = ctx.state.templates[sid];

    uint32_t tmpl_lifetime = ctx.result.timestamp - tmpl.timestamp;

    if (tmpl_lifetime > ctx.state.template_expire_time) {
        ++ctx.state.stats.expired_templates;
        ctx.state.templates.erase(sid);
        ctx.buf.advance(ctx.buf.remaining());
        return true;
    }

    while (ctx.buf.remaining() > 0) {
        if (!parse_flow(ctx, tmpl, f))
            return false;
    }

    ctx.result.flowsets.emplace_back(std::move(f));

    return true;
}

static bool parse_flowset(parsing_context& context)
{
    flowset_header header;

    if (!context.buf.get(&header, sizeof(header)))
        return false;

    size_t flowset_length = ntohs(header.length);

    // The length must be at least 4 because each flowset has at
    // least two uint16_t fields: flowset_id and the length field
    // itself.
    if (flowset_length < sizeof(header))
        return false;

    flowset_length -= sizeof(header);
    if (flowset_length > context.buf.remaining())
        return false;

    buffer tmpbuf{context.buf.ptr, flowset_length, context.buf.ptr};
    context.buf.advance(flowset_length);

    parsing_context ctx = {tmpbuf, context.source_id, context.srcaddr,
                           context.result, context.state};

    uint16_t flowset_id = ntohs(header.flowset_id);

    switch (get_flowset_type(flowset_id)) {
        case NF9_FLOWSET_TEMPLATE:
            context.state.stats.data_templates++;
            return parse_data_template_flowset(ctx);
        case NF9_FLOWSET_OPTIONS:
            context.state.stats.option_templates++;
            return parse_option_template_flowset(ctx);
        case NF9_FLOWSET_DATA:
            context.state.stats.records++;
            return parse_data_flowset(ctx, flowset_id);
        default:
            context.state.stats.malformed_packets++;
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

    if (!parse_header(buf, header, result->timestamp, result->system_uptime))
        return false;

    result->src_id = ntohl(header.source_id);

    parsing_context context = {buf, ntohl(header.source_id), srcaddr, *result,
                               *state};

    size_t num_flowsets = ntohs(header.count);
    for (size_t i = 0; i < num_flowsets && buf.remaining() > 0; ++i) {
        if (!parse_flowset(context))
            return false;
    }

    return true;
}
