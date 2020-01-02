#ifndef PARSE_H
#define PARSE_H

#include <netflow9.h>
#include "types.h"

bool parse(const uint8_t* buf, size_t len, nf9_state* state,
           nf9_parse_result* result);

#endif
