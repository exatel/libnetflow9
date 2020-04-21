/*
 * Copyright © 2019-2020 Exatel S.A.
 * Contact: github@exatel.pl
 * LICENSE: LGPL-3.0-or-later, See COPYING*.md files.
 */

#include "storage.h"
#include <cassert>
#include <mutex>

void* limited_memory_resource::do_allocate(std::size_t bytes,
                                           std::size_t alignment)
{
    if (bytes > max_size_ - used_)
        throw out_of_memory_error("Memory limit has been reached");
    pmr::memory_resource* mr = pmr::new_delete_resource();
    void* result = mr->allocate(bytes, alignment);
    used_ += bytes;
    return result;
}

void limited_memory_resource::do_deallocate(void* p, std::size_t bytes,
                                            std::size_t alignment)
{
    pmr::memory_resource* mr = pmr::new_delete_resource();
    mr->deallocate(p, bytes, alignment);
    used_ -= bytes;
}

bool limited_memory_resource::do_is_equal(
    const pmr::memory_resource& other) const noexcept
{
    return this == &other;
}

size_t limited_memory_resource::get_current() const
{
    return used_;
}

void limited_memory_resource::set_limit(size_t max_mem)
{
    max_size_ = max_mem;
}

template <typename T>
int delete_expired_objects(uint32_t timestamp, uint32_t expire_time,
                           T& stored_map, nf9_stats& stats)
{
    int deleted_objects = 0;
    uint32_t expiration_timestamp;
    if (timestamp > expire_time)
        expiration_timestamp = timestamp - expire_time;
    else
        expiration_timestamp = 0;

    for (auto it = stored_map.begin(); it != stored_map.end();) {
        if (it->second.timestamp <= expiration_timestamp) {
            ++deleted_objects;
            ++stats.expired_templates;
            it = stored_map.erase(it);
        }
        else {
            ++it;
        }
    }
    return deleted_objects;
}

void assign_template(nf9_state& state, data_template& tmpl, stream_id& sid)
{
    state.templates.insert_or_assign(
        sid, data_template{
                 {tmpl.fields.begin(), tmpl.fields.end(), state.memory.get()},
                 tmpl.total_length,
                 tmpl.timestamp,
                 tmpl.is_option});
}

bool save_template(data_template& tmpl, stream_id& sid, nf9_state& state,
                   nf9_packet& result)
{
    if (tmpl.total_length == 0)
        return false;
    if (state.templates.count(sid) != 0 &&
        (tmpl.timestamp < state.templates[sid].timestamp))
        return false;

    try {
        assign_template(state, tmpl, sid);
    } catch (const out_of_memory_error&) {
        int deleted =
            delete_expired_objects(result.timestamp, state.template_expire_time,
                                   state.templates, state.stats);
        if (deleted == 0)
            return false;

        try {
            assign_template(state, tmpl, sid);
        } catch (const out_of_memory_error&) {
            return false;
        }
    }
    assert(state.templates[sid].fields.get_allocator().resource() ==
           state.memory.get());

    return true;
}

void assign_option(nf9_state& state, device_options& dev_opts,
                   device_id& dev_id)
{
    std::lock_guard<std::mutex> lock(state.options_mutex);
    state.options.insert_or_assign(
        dev_id, device_options{flow(flow::allocator_type(state.memory.get())),
                               dev_opts.timestamp});
    for (auto& [field, value] : dev_opts.options_flow) {
        auto [inserted_value, _] =
            state.options[dev_id].options_flow.insert_or_assign(
                field, pmr::vector<uint8_t>(state.memory.get()));
        inserted_value->second.assign(value.begin(), value.end());
    }
}

bool save_option(nf9_state& state, device_id& dev_id, device_options& dev_opts)
{
    try {
        assign_option(state, dev_opts, dev_id);
    } catch (const out_of_memory_error&) {
        int deleted =
            delete_expired_objects(dev_opts.timestamp, state.option_expire_time,
                                   state.options, state.stats);
        if (deleted == 0)
            return false;

        try {
            assign_option(state, dev_opts, dev_id);
        } catch (const out_of_memory_error&) {
            return false;
        }
    }
    assert(state.options[dev_id]
               .options_flow.begin()
               ->second.get_allocator()
               .resource() == state.memory.get());

    return true;
}

bool save_sampling_rate(nf9_state& state, sampler_id sid, uint32_t rate)
{
    try {
        state.sampling_rates.insert_or_assign(sid, rate);
        return true;
    } catch (const out_of_memory_error&) {
        return false;
    }
}
