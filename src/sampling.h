/*
 * Copyright © 2019-2020 Exatel S.A.
 * Contact: github@exatel.pl
 * LICENSE: LGPL-3.0-or-later, See COPYING*.md files.
 */

#ifndef SAMPLING_H
#define SAMPLING_H

#include <netflow9.h>
#include "types.h"

/* Extract sampling rate from given *options* flow and save it for given
 * Exporter device. */
bool save_sampling_info(nf9_state& st, const flow& f, const device_id& did);

#endif
