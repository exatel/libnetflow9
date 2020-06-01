/*
 * Copyright © 2019-2020 Exatel S.A.
 * Contact: opensource@exatel.pl
 * LICENSE: LGPL-3.0-or-later, See COPYING*.md files.
 */

#include "sampling.h"
#include <cstring>
#include "storage.h"

int save_sampling_info(nf9_state& st, const flow& f, const device_id& did)
{
    uint32_t rate;
    uint16_t sampler;
    const pmr::vector<uint8_t>* value_bytes;

    // First, find two fields in the flow: sampling interval and sampler id.
    // TODO: Consider SAMPLING_INTERVAL
    if (f.count(NF9_FIELD_FLOW_SAMPLER_RANDOM_INTERVAL) == 0 ||
        f.count(NF9_FIELD_FLOW_SAMPLER_ID) == 0)
        return NF9_ERR_NOT_FOUND;

    // Extract the rate
    value_bytes = &f.at(NF9_FIELD_FLOW_SAMPLER_RANDOM_INTERVAL);
    if (value_bytes->size() != sizeof(rate)) {
        // TODO: Handle this error better.
        return NF9_ERR_NOT_FOUND;
    }
    memcpy(static_cast<void*>(&rate),
           static_cast<const void*>(value_bytes->data()), value_bytes->size());
    rate = ntohl(rate);

    // Extract sampler id
    value_bytes = &f.at(NF9_FIELD_FLOW_SAMPLER_ID);
    if (value_bytes->size() != sizeof(sampler)) {
        // TODO: Handle this error better.
        return NF9_ERR_NOT_FOUND;
    }
    memcpy(static_cast<void*>(&sampler),
           static_cast<const void*>(value_bytes->data()), value_bytes->size());
    sampler = ntohs(sampler);

    // Now save the rate.
    if (int err = save_sampling_rate(st, sampler_id{did, sampler}, rate);
        err != 0)
        return err;

    return 0;
}
