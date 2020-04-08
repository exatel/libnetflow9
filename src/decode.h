/*
 * Copyright © 2019-2020 Exatel S.A.
 * Contact: github@exatel.pl
 * LICENSE: LGPL-3.0-or-later, See COPYING*.md files.
 */

#ifndef DECODE_H
#define DECODE_H

#include <netflow9.h>
#include "types.h"

bool decode(const uint8_t* buf, size_t len, const nf9_addr& addr,
            nf9_state* state, nf9_packet* result);

#endif
