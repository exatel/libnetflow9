/*
 * Copyright © 2019-2020 Exatel S.A.
 * Contact: github@exatel.pl
 * LICENSE: LGPL-3.0-or-later, See COPYING*.md files.
 */

#include <arpa/inet.h>
#include <netflow9.h>
#include <string.h>

/* This file contains a fuzzer for libnetflow.
 * To build it, run cmake with -DNF9_FUZZ=ON and -DCMAKE_CXX_COMPILER=clang++.
 *
 * Then, run: ./fuzz/netflowfuzz ../fuzz/corpus
 */

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    nf9_state *st = nf9_init(0);
    nf9_parse_result *pr;
    nf9_addr addr;
    memset(&addr, 0, sizeof(addr));

    addr.family = AF_INET;
    addr.in.sin_addr.s_addr = 12345;

    nf9_parse(st, &pr, data, size, &addr);
    if (pr)
        nf9_free_parse_result(pr);

    nf9_free(st);
    return 0;
}
