#include <arpa/inet.h>
#include <netflow9.h>
#include <cstdlib>
#include <cstring>

/* This file contains a fuzzer for libnetflow.
 * To build it, run cmake with -DNF9_FUZZ=ON and -DCMAKE_CXX_COMPILER=clang++.
 *
 * Then, run: ./fuzz/netflowfuzz ../fuzz/corpus
 */

namespace
{
nf9_state *state;

// Dummy variables.
size_t total_flowsets = 0;
size_t total_template_flowsets = 0;
size_t total_option_flowsets = 0;
size_t total_data_flowsets = 0;
size_t total_flows = 0;
size_t total_bytes = 0;
}  // namespace

extern "C" void LLVMFuzzerInitialize()
{
    state = nf9_init(0);

    if (nf9_ctl(state, NF9_OPT_MAX_MEM_USAGE, 1024 * 1000))
        abort();

    if (nf9_ctl(state, NF9_OPT_TEMPLATE_EXPIRE_TIME, 5))
        abort();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    nf9_parse_result *pr;
    nf9_addr addr;
    memset(&addr, 0, sizeof(addr));

    addr.family = AF_INET;
    addr.in.sin_addr.s_addr = 12345;

    nf9_parse(state, &pr, data, size, &addr);
    if (pr) {
        // Increment the dummy counters based on the parsed packet.  We do this
        // to have more branches in code, to help the fuzzer.

        size_t nflowsets = nf9_get_num_flowsets(pr);
        total_flowsets += nflowsets;

        for (unsigned i = 0; i < nflowsets; i++) {
            switch (nf9_get_flowset_type(pr, i)) {
                case NF9_FLOWSET_TEMPLATE:
                    total_template_flowsets++;
                    break;
                case NF9_FLOWSET_OPTIONS:
                    total_option_flowsets++;
                    break;
                case NF9_FLOWSET_DATA: {
                    total_data_flowsets++;

                    size_t nflows = nf9_get_num_flows(pr, i);
                    total_flows += nflows;

                    // Simulate counting bytes.
                    for (unsigned j = 0; j < nflows; j++) {
                        size_t nbytes;
                        size_t size = sizeof(size_t);

                        if (nf9_get_field(pr, i, j, NF9_FIELD_IN_BYTES, &nbytes,
                                          &size))
                            continue;

                        total_bytes += nbytes;
                    }
                    break;
                }
                default:
                    abort();
            }
        }

        nf9_free_parse_result(pr);
    }

    return 0;
}
