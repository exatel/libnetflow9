/*
 * Copyright © 2019-2020 Exatel S.A.
 * Contact: opensource@exatel.pl
 * LICENSE: LGPL-3.0-or-later, See COPYING*.md files.
 */

#ifndef STORAGE_H
#define STORAGE_H

#include <netflow9.h>
#include <stdexcept>
#include "types.h"

struct out_of_memory_error : public std::runtime_error
{
    using std::runtime_error::runtime_error;
};

int save_template(data_template& tmpl, stream_id& sid, nf9_state& state,
                  nf9_packet& result);

int save_option(nf9_state& state, device_id& dev_id, device_options& dev_opts);

int save_sampling_rate(nf9_state& state, const device_id& did, uint32_t sid,
                       uint32_t rate);

#endif
