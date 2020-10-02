/*
 * Copyright © 2019-2020 Exatel S.A.
 * Contact: opensource@exatel.pl
 * LICENSE: LGPL-3.0-or-later, See COPYING*.md files.
 */

#include "decode.h"
#include <cassert>
#include <cstring>
#include "sampling.h"
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

struct context
{
    buffer& buf;
    uint32_t source_id;
    const nf9_addr& srcaddr;
    nf9_packet& result;
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

static int decode_header(buffer& buf, netflow_header& hdr, uint32_t& timestamp,
                         uint32_t& uptime)
{
    if (!buf.get(&hdr, sizeof(hdr)))
        return NF9_ERR_MALFORMED;

    if (ntohs(hdr.version) != 9)
        return NF9_ERR_MALFORMED;

    timestamp = ntohl(hdr.timestamp);
    uptime = ntohl(hdr.uptime);

    return 0;
}

static int decode_template_field(buffer& buf, uint16_t& type, uint16_t& length)
{
    if (!buf.get(&type, sizeof(type)))
        return NF9_ERR_MALFORMED;

    if (!buf.get(&length, sizeof(length)))
        return NF9_ERR_MALFORMED;

    type = ntohs(type);
    length = ntohs(length);

    if (length == 0)
        return NF9_ERR_MALFORMED;
    return 0;
}

static int decode_data_template(buffer& buf, data_template& tmpl,
                                nf9_packet& result)
{
    uint16_t type;
    uint16_t length;

    if (int err = decode_template_field(buf, type, length); err != 0)
        return err;

    tmpl.fields.emplace_back(NF9_DATA_FIELD(type), length);
    tmpl.total_length += length;
    tmpl.timestamp = result.timestamp;
    tmpl.is_option = false;

    return 0;
}

static int decode_data_template_flowset(context& ctx)
{
    while (ctx.buf.remaining() > 0) {
        data_template_header header;
        if (!ctx.buf.get(&header, sizeof(header)))
            return NF9_ERR_MALFORMED;

        flowset f = flowset();
        f.type = NF9_FLOWSET_TEMPLATE;
        data_template& tmpl = f.dtemplate;
        uint16_t field_count = ntohs(header.field_count);

        while (field_count-- > 0 && ctx.buf.remaining() > 0) {
            if (int err = decode_data_template(ctx.buf, tmpl, ctx.result);
                err != 0)
                return err;
        }

        stream_id sid = {device_id{ctx.srcaddr, ctx.source_id},
                         ntohs(header.template_id)};

        if (int err = save_template(tmpl, sid, ctx.state, ctx.result); err != 0)
            return err;

        ctx.result.flowsets.emplace_back(std::move(f));
    }
    return 0;
}

static int decode_option_template(buffer& buf, data_template& tmpl,
                                  uint16_t option_scope_length,
                                  uint16_t option_length, uint32_t timestamp)
{
    uint16_t type;
    uint16_t length;

    while (option_scope_length && buf.remaining() > 0) {
        if (int err = decode_template_field(buf, type, length); err != 0)
            return NF9_ERR_MALFORMED;
        if (length == 0)
            return NF9_ERR_MALFORMED;

        nf9_field field_type = NF9_SCOPE_FIELD(type);
        tmpl.fields.emplace_back(field_type, length);
        tmpl.total_length += length;
        if (option_scope_length < sizeof(type) + sizeof(length))
            return NF9_ERR_MALFORMED;
        option_scope_length -= sizeof(type) + sizeof(length);
    }

    while (option_length && buf.remaining() > 0) {
        if (int err = decode_template_field(buf, type, length); err != 0)
            return err;
        if (length == 0)
            return NF9_ERR_MALFORMED;

        nf9_field field_type = NF9_DATA_FIELD(type);
        tmpl.fields.emplace_back(field_type, length);
        tmpl.total_length += length;
        if (option_length < sizeof(type) + sizeof(length))
            return NF9_ERR_MALFORMED;
        option_length -= sizeof(type) + sizeof(length);
    }
    tmpl.timestamp = timestamp;
    tmpl.is_option = true;

    return 0;
}

static int decode_option_template_flowset(context& ctx)
{
    // TODO: Consider decoding flowsets with multiple option templates
    option_template_header header;
    if (!ctx.buf.get(&header, sizeof(header)))
        return NF9_ERR_MALFORMED;

    flowset f = flowset();
    f.type = NF9_FLOWSET_OPTIONS;
    data_template& tmpl = f.dtemplate;

    if (int err = decode_option_template(
            ctx.buf, tmpl, ntohs(header.option_scope_length),
            ntohs(header.option_length), ctx.result.timestamp);
        err != 0)
        return err;

    stream_id sid = {device_id{ctx.srcaddr, ctx.source_id},
                     ntohs(header.template_id)};

    if (int err = save_template(tmpl, sid, ctx.state, ctx.result); err != 0)
        return err;

    ctx.result.flowsets.emplace_back(std::move(f));

    // omit padding bytes
    ctx.buf.advance(ctx.buf.remaining());
    return 0;
}

static int decode_flow(context& ctx, data_template& tmpl, flowset& result)
{
    if (tmpl.fields.empty()) {
        ctx.buf.advance(ctx.buf.remaining());
        return 0;
    }

    if (tmpl.total_length > ctx.buf.remaining()) {
        ctx.buf.advance(ctx.buf.remaining());
        return 0;
    }

    flow f = flow();

    for (const template_field& tf : tmpl.fields) {
        uint32_t type = tf.first;
        size_t field_length = tf.second;

        if (field_length > ctx.buf.remaining())
            return NF9_ERR_MALFORMED;

        if (field_length == 0)
            break;

        pmr::vector<uint8_t> field_value(field_length, 0);
        ctx.buf.get(field_value.data(), field_length);

        f[type] = field_value;
    }

    if (tmpl.is_option) {
        device_id dev_id = {ctx.srcaddr, ctx.source_id};
        device_options dev_opts = {f, ctx.result.timestamp};
        if (int err = save_option(ctx.state, dev_id, dev_opts); err != 0)
            return err;

        if (ctx.state.store_sampling_rates) {
            // Save sampling rates if the user enabled that.

            // FIXME: handle error once proper enums are defined.
            save_sampling_info(ctx.state, f, dev_id);
        }
    }

    result.flows.emplace_back(std::move(f));
    return 0;
}

static int decode_data_flowset(context& ctx, uint16_t flowset_id)
{
    stream_id sid = {device_id{ctx.srcaddr, ctx.source_id}, flowset_id};

    flowset f = flowset();
    f.type = NF9_FLOWSET_DATA;

    if (ctx.state.templates.count(sid) == 0) {
        ++ctx.state.stats.missing_template_errors;
        ctx.buf.advance(ctx.buf.remaining());
        return 0;
    }

    data_template& tmpl = ctx.state.templates[sid];

    uint32_t tmpl_lifetime = ctx.result.timestamp - tmpl.timestamp;

    if (tmpl_lifetime > ctx.state.template_expire_time) {
        ++ctx.state.stats.expired_templates;
        ctx.state.templates.erase(sid);
        ctx.buf.advance(ctx.buf.remaining());
        return 0;
    }

    while (ctx.buf.remaining() > 0) {
        if (int err = decode_flow(ctx, tmpl, f); err != 0)
            return err;
    }

    ctx.result.flowsets.emplace_back(std::move(f));

    return 0;
}

static int decode_flowset(context& ctx)
{
    flowset_header header;

    if (!ctx.buf.get(&header, sizeof(header)))
        return NF9_ERR_MALFORMED;

    uint16_t flowset_length = ntohs(header.length);

    // The length must be at least 4 because each flowset has at
    // least two uint16_t fields: flowset_id and the length field
    // itself.
    if (flowset_length < sizeof(header))
        return NF9_ERR_MALFORMED;

    flowset_length -= sizeof(header);
    if (flowset_length > ctx.buf.remaining())
        return NF9_ERR_MALFORMED;

    buffer tmpbuf{ctx.buf.ptr, flowset_length, ctx.buf.ptr};
    ctx.buf.advance(flowset_length);

    context sub_ctx = {tmpbuf, ctx.source_id, ctx.srcaddr, ctx.result,
                       ctx.state};

    uint16_t flowset_id = ntohs(header.flowset_id);

    switch (get_flowset_type(flowset_id)) {
        case NF9_FLOWSET_TEMPLATE:
            ctx.state.stats.data_templates++;
            return decode_data_template_flowset(sub_ctx);
        case NF9_FLOWSET_OPTIONS:
            ctx.state.stats.option_templates++;
            return decode_option_template_flowset(sub_ctx);
        case NF9_FLOWSET_DATA:
            ctx.state.stats.records++;
            return decode_data_flowset(sub_ctx, flowset_id);
        default:
            ctx.state.stats.malformed_packets++;
            return NF9_ERR_MALFORMED;
    }

    // Unreachable
    assert(0);
}

int decode(const uint8_t* data, size_t len, const nf9_addr& srcaddr,
           nf9_state* state, nf9_packet* result)
{
    buffer buf{data, len, data};
    netflow_header header;

    if (int err = decode_header(buf, header, result->timestamp,
                                result->system_uptime);
        err != 0)
        return NF9_ERR_MALFORMED;

    result->src_id = ntohl(header.source_id);

    context ctx = {buf, ntohl(header.source_id), srcaddr, *result, *state};

    size_t num_flowsets = ntohs(header.count);
    for (size_t i = 0; i < num_flowsets && buf.remaining() > 0; ++i) {
        if (int err = decode_flowset(ctx); err != 0)
            return err;
    }

    return 0;
}
