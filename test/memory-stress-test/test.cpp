#include <netflow9.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <iostream>
#include <vector>

#include "test_lib.h"

// *******************************************************************************
// Memory stress test.
//
// This test program will create a `nf9_state' and set a memory usage limit via
// `nf9_ctl'.  Then it will loop, feeding the state random templates,
// printing actual and reported (by nf9_get_stat) memory usage to stdout.
//
// *******************************************************************************

namespace
{
constexpr size_t MAX_MEM = 300'000'000;  // Bytes.

time_t start_time = time(NULL);

int random(int from, int to)
{
    int range = to - from;
    return rand() % range + from;
}

size_t get_self_memusage()
{
    std::ifstream in("/proc/self/statm");

    size_t ret = 0;
    in >> ret;  // discard first column
    in >> ret;

    return ret * getpagesize();
}

void print_stats(nf9_state* st)
{
    static time_t print_time;
    print_time = time(NULL);

    const nf9_stats* stats = nf9_get_stats(st);

    time_t program_uptime = (print_time - start_time);
    double actual_memusage = get_self_memusage() / 1'000'000.0;
    double reported_memusage =
        nf9_get_stat(stats, NF9_STAT_MEMORY_USAGE) / 1'000'000.0;

    std::cout << program_uptime << "s: actual=" << actual_memusage << "MB "
              << "reported=" << reported_memusage << "MB\n";

    nf9_free_stats(stats);
}

std::vector<uint8_t> generate_packet()
{
    return netflow_packet_builder()
        .add_data_template_flowset(random(0, 255))
        .add_data_template(uint16_t(random(256, 65536)))
        .add_data_template_field(NF9_FIELD_IPV4_SRC_ADDR, 4)
        .add_data_template_field(NF9_FIELD_IPV4_DST_ADDR, 4)
        .build();
}

const nf9_addr* generate_address()
{
    static nf9_addr addr;
    addr.family = AF_INET;
    addr.in.sin_addr.s_addr = random(1, 1 << 31);
    addr.in.sin_port = uint16_t(random(1024, 65536));

    return &addr;
}

}  // namespace

int main(int argc, char** argv)
{
    nf9_state* st = nf9_init(0);
    time_t print_time = 0;

    nf9_ctl(st, NF9_OPT_MAX_MEM_USAGE, MAX_MEM);

    while (true) {
        std::vector<uint8_t> packet = generate_packet();
        nf9_parse_result* pr;
        if (!nf9_parse(st, &pr, packet.data(), packet.size(),
                       generate_address()))
            nf9_free_parse_result(pr);

        time_t t;
        if ((t = time(NULL)) > print_time) {
            print_stats(st);
            print_time = t;
        }
    }

    nf9_free(st);
}
