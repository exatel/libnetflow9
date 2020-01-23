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

struct parsing_context
{
    buffer& buf;
    uint32_t source_id;
    const nf9_addr& srcaddr;
    nf9_parse_result& result;
    nf9_state& state;
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

static size_t get_template_size(const data_template& tmpl)
{
    size_t tmpl_size =
        sizeof(data_template) + tmpl.fields.size() * sizeof(template_field);
    return tmpl_size;
}

static int delete_expired_templates(uint32_t timestamp, nf9_state& state)
{
    int deleted_templates = 0;
    uint32_t expiration_timestamp;
    if (timestamp > state.template_expire_time)
        expiration_timestamp = timestamp - state.template_expire_time;
    else
        expiration_timestamp = 0;

    for (auto it = state.templates.begin(); it != state.templates.end();) {
        if (it->second.timestamp <= expiration_timestamp) {
            ++deleted_templates;
            ++state.stats.expired_templates;
            state.used_bytes -= get_template_size(it->second);
            it = state.templates.erase(it);
        }
        else {
            ++it;
        }
    }
    return deleted_templates;
}

static bool save_template(data_template& tmpl, parsing_context& ctx,
                          uint16_t tid)
{
    if (tmpl.total_length == 0)
        return false;

    size_t bytes_to_allocate = get_template_size(tmpl);

    if (ctx.state.used_bytes + bytes_to_allocate >=
        ctx.state.max_template_data) {
        int deleted = delete_expired_templates(ctx.result.timestamp, ctx.state);
        if (deleted == 0)
            return false;
        else if (ctx.state.used_bytes + bytes_to_allocate >=
                 ctx.state.max_template_data)
            return false;
    }

    stream_id sid = {device_id{ctx.srcaddr, ctx.source_id}, ntohs(tid)};
    if (ctx.state.templates.count(sid) != 0) {
        if (tmpl.timestamp >= ctx.state.templates[sid].timestamp)
            ctx.state.used_bytes -= get_template_size(ctx.state.templates[sid]);
        else
            return true;
    }
    ctx.state.templates[sid] = tmpl;

    /* Increment counter of bytes allocated by templates */
    ctx.state.used_bytes += bytes_to_allocate;

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

        if (!save_template(tmpl, ctx, header.template_id))
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

    if (!save_template(tmpl, ctx, header.template_id))
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

        std::vector<uint8_t> field_value(field_length, 0);
        ctx.buf.get(field_value.data(), field_length);

        f[type] = field_value;
    }

    if (tmpl.is_option) {
        device_id dev_id = {ctx.srcaddr, ctx.source_id};
        ctx.state.options[dev_id].option_flow = f;
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

    switch (get_flowset_type(header)) {
        case NF9_FLOWSET_TEMPLATE:
            context.state.stats.data_templates++;
            return parse_data_template_flowset(ctx);
        case NF9_FLOWSET_OPTIONS:
            context.state.stats.option_templates++;
            return parse_option_template_flowset(ctx);
        case NF9_FLOWSET_DATA:
            context.state.stats.records++;
            return parse_data_flowset(ctx, ntohs(header.flowset_id));
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

    parsing_context context = {buf, ntohl(header.source_id), srcaddr, *result,
                               *state};

    size_t num_flowsets = ntohs(header.count);
    for (size_t i = 0; i < num_flowsets && buf.remaining() > 0; ++i) {
        if (!parse_flowset(context))
            return false;
    }

    return true;
}
