#ifndef PARSE_H
#define PARSE_H

#include <netflow9.h>
#include "types.h"

enum class nf9_rc { RESULT_OK, RESULT_ERR };

nf9_rc parse(nf9_state* state, const uint8_t* buf, size_t len,
             nf9_parse_result* result);

#endif
