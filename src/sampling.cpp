/*
 * Copyright © 2019-2020 Exatel S.A.
 * Contact: opensource@exatel.pl
 * LICENSE: LGPL-3.0-or-later, See COPYING*.md files.
 */

#include "sampling.h"
#include <climits>
#include <cstring>
#include "storage.h"

static int extract_u32_field(const flow& f, nf9_field field, uint32_t* dst)
{
    const pmr::vector<uint8_t>* value_bytes = nullptr;
    try {
        value_bytes = &f.at(field);
    } catch (std::exception& e) {
        return NF9_ERR_NOT_FOUND;
    }
    size_t size = value_bytes->size();

    if (size > sizeof(*dst)) {
        // TODO: Handle this error better.
        return NF9_ERR_MALFORMED;
    }

    memcpy(static_cast<void*>(dst),
           static_cast<const void*>(value_bytes->data()), size);

#ifdef NF9_IS_BIG_ENDIAN
    *dst >>= (sizeof(*dst) - size) * CHAR_BIT;
#else
    *dst <<= (sizeof(*dst) - size) * CHAR_BIT;
#endif

    *dst = ntohl(*dst);

    return 0;
}

int save_sampling_info(nf9_state& st, const flow& f, const device_id& did)
{
    uint32_t rate = 0;
    uint32_t sampler = 0;

    // TODO: Consider SAMPLING_INTERVAL
    if (int err =
            extract_u32_field(f, NF9_FIELD_FLOW_SAMPLER_RANDOM_INTERVAL, &rate);
        err != 0) {
        return err;
    }

    if (int err = extract_u32_field(f, NF9_FIELD_FLOW_SAMPLER_ID, &sampler);
        err != 0) {
        return err;
    }

    if (int err = save_sampling_rate(st, did, sampler, rate); err != 0)
        return err;

    return 0;
}
