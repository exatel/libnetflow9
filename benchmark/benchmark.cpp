/*
 * Copyright © 2019-2020 Exatel S.A.
 * Contact: github@exatel.pl
 * LICENSE: LGPL-3.0-or-later, See COPYING*.md files.
 */

#include <benchmark/benchmark.h>
#include <netflow9.h>
#include <cstdlib>
#include <vector>
#include "test_lib.h"

std::vector<uint8_t> generate_packet()
{
    uint16_t template_id = rand() % (1 << sizeof(uint16_t));
    if (template_id <= 255)
        template_id = 256;

    return netflow_packet_builder()
        .add_data_template_flowset(0)
        .add_data_template(template_id)
        .add_data_template_field(NF9_FIELD_IPV4_SRC_ADDR, 4)
        .add_data_template_field(NF9_FIELD_IPV4_DST_ADDR, 4)
        .add_data_flowset(template_id)
        .add_data_field(uint32_t(401023))
        .add_data_field(uint32_t(401024))
        .build();
}

static void bm_nf9_parse(benchmark::State &state)
{
    for (auto _ : state) {
        nf9_addr addr;
        nf9_state *st = nf9_init(0);

        addr.family = AF_INET;
        addr.in.sin_addr.s_addr = 123456;

        const std::vector<uint8_t> &pkt = generate_packet();
        nf9_parse_result *pr;
        nf9_parse(st, &pr, pkt.data(), pkt.size(), &addr);
        nf9_free_parse_result(pr);

        nf9_free(st);
    }
}

static void bm_nf9_parse_large_data_flowset(benchmark::State &state)
{
    const size_t NFIELDS = 1024;

    nf9_addr addr;
    nf9_state *st = nf9_init(0);
    nf9_parse_result *pr;
    std::vector<uint8_t> packet;
    netflow_packet_builder builder;

    addr.family = AF_INET;
    addr.in.sin_addr.s_addr = 123456;

    // Build a data template
    builder.add_data_template_flowset(123);
    builder.add_data_template(400);
    for (size_t i = 0; i < NFIELDS; i++)
        builder.add_data_template_field(NF9_FIELD_IPV4_DST_ADDR, 4);

    packet = builder.build();
    nf9_parse(st, &pr, packet.data(), packet.size(), &addr);

    // Now build a data flowset packet
    builder = netflow_packet_builder();
    builder.add_data_flowset(400);
    for (size_t i = 0; i < NFIELDS; i++)
        builder.add_data_field(uint32_t(i));

    packet = builder.build();

    for (auto _ : state) {
        nf9_parse(st, &pr, packet.data(), packet.size(), &addr);
        nf9_free_parse_result(pr);
    }
    nf9_free(st);
}

static void bm_nf9_options(benchmark::State &state)
{
    nf9_addr addr;
    nf9_state *st = nf9_init(0);
    nf9_parse_result *pr;
    std::vector<uint8_t> packet;
    netflow_packet_builder builder;

    addr.family = AF_INET;
    addr.in.sin_addr.s_addr = 123456;

    // Build an option template
    builder.add_option_template_flowset(444);
    builder.add_option_field(NF9_FIELD_IPV4_DST_ADDR, 4);

    packet = builder.build();
    nf9_parse(st, &pr, packet.data(), packet.size(), &addr);

    // Now build a data flowset with options
    builder = netflow_packet_builder();
    builder.add_data_flowset(444);
    builder.add_data_field(uint32_t(12345));

    packet = builder.build();

    for (auto _ : state) {
        nf9_parse(st, &pr, packet.data(), packet.size(), &addr);

        uint32_t tmp;
        size_t size = sizeof(tmp);
        nf9_get_option(pr, NF9_FIELD_IPV4_DST_ADDR, &tmp, &size);
        nf9_free_parse_result(pr);
    }
    nf9_free(st);
}

BENCHMARK(bm_nf9_parse);
BENCHMARK(bm_nf9_parse_large_data_flowset);
BENCHMARK(bm_nf9_options);

BENCHMARK_MAIN();
