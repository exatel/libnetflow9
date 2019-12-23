#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netflow9.h>
#include <netinet/in.h>
#include <tins/tins.h>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include "test_lib.h"

std::vector<nf9_parse_result *> parse_pcap(nf9_state *state, std::string path)
{
    auto packets = get_packets(path.c_str());

    std::vector<nf9_parse_result *> parsed;

    for (const auto &packet : packets) {
        nf9_parse_result *result;
        if (nf9_parse(state, &result, packet.data, packet.len, &packet.addr))
            continue;
        parsed.push_back(result);
    }

    return parsed;
}

TEST(PCAPTest, BasicTest)
{
    nf9_state *state = nf9_init(0);
    std::vector<nf9_parse_result *> parsed_pcap =
        parse_pcap(state, "testcases/1.pcap");
    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("172.17.0.5");
    EXPECT_EQ(nf9_get_addr(parsed_pcap[6]).sin_addr.s_addr,
              0 /* address.sin_addr.s_addr */);
    // EXPECT_EQ(nf9_get_addr(parsed_pcap[8]);
    std::vector<uint32_t> src_ips;
    for (const auto &parse_result : parsed_pcap) {
        for (size_t flowset = 0; flowset < nf9_get_num_flowsets(parse_result);
             ++flowset) {
            for (size_t flow = 0;
                 flow < nf9_get_num_flows(parse_result, flowset); ++flow) {
                nf9_value field = nf9_get_field(parse_result, flowset, flow,
                                                NF9_FIELD_IPV4_SRC_ADDR);
                src_ips.push_back(field.u32);
            }
        }
        nf9_free_parse_result(parse_result);
    }

    EXPECT_EQ(src_ips.size(), 0);  // 2

    nf9_free(state);
}

TEST(PCAPTest, BasicStatsTest)
{
    nf9_state *state = nf9_init(0);
    std::vector<nf9_parse_result *> parse_result =
        parse_pcap(state, "testcases/1.pcap");

    const nf9_stats *stats = nf9_get_stats(state);

    EXPECT_EQ(nf9_get_stat(stats, NF9_STAT_TOTAL_RECORDS), 0 /* 4 */);
    EXPECT_EQ(nf9_get_stat(stats, NF9_STAT_TOTAL_TEMPLATES), 0 /* 4 */);
    EXPECT_EQ(nf9_get_stat(stats, NF9_STAT_TOTAL_OPTION_TEMPLATES), 0 /* 2 */);
    EXPECT_EQ(nf9_get_stat(stats, NF9_STAT_MISSING_TEMPLATE_ERRORS), 0);
    EXPECT_EQ(nf9_get_stat(stats, NF9_STAT_MALFORMED_PACKETS), 0 /* 5 */);

    for (auto *pr : parse_result)
        nf9_free_parse_result(pr);
    nf9_free_stats(stats);
    nf9_free(state);
}

TEST(PCAPTest, Malformed1Test)
{
    nf9_state *state = nf9_init(0);
    std::vector<nf9_parse_result *> parse_result =
        parse_pcap(state, "testcases/malformed_1.pcap");

    const nf9_stats *stats = nf9_get_stats(state);

    EXPECT_EQ(nf9_get_stat(stats, NF9_STAT_MALFORMED_PACKETS), 0 /* 3 */);

    for (auto *pr : parse_result)
        nf9_free_parse_result(pr);
    nf9_free_stats(stats);
    nf9_free(state);
}

TEST(PCAPTest, Malformed2Test)
{
    nf9_state *state = nf9_init(0);
    std::vector<nf9_parse_result *> parse_result =
        parse_pcap(state, "testcases/malformed_2.pcap");

    const nf9_stats *stats = nf9_get_stats(state);

    EXPECT_EQ(nf9_get_stat(stats, NF9_STAT_MALFORMED_PACKETS), 0 /* 19 */);

    for (auto *pr : parse_result)
        nf9_free_parse_result(pr);
    nf9_free_stats(stats);
    nf9_free(state);
}

TEST(PCAPTest, Malformed3Test)
{
    nf9_state *state = nf9_init(0);
    std::vector<nf9_parse_result *> parse_result =
        parse_pcap(state, "testcases/malformed_3.pcap");

    const nf9_stats *stats = nf9_get_stats(state);

    EXPECT_EQ(nf9_get_stat(stats, NF9_STAT_MALFORMED_PACKETS), 0 /* 20 */);

    for (auto *pr : parse_result)
        nf9_free_parse_result(pr);
    nf9_free_stats(stats);
    nf9_free(state);
}

TEST(PCAPTest, Malformed4Test)
{
    /* The PCAP contains a Netflow packet where one flowset
     * has length that equals zero.
     */
    nf9_state *state = nf9_init(0);
    std::vector<nf9_parse_result *> parse_result =
        parse_pcap(state, "testcases/malformed_4.pcap");

    const nf9_stats *stats = nf9_get_stats(state);

    EXPECT_EQ(nf9_get_stat(stats, NF9_STAT_MALFORMED_PACKETS), 0 /* 1 */);

    for (auto *pr : parse_result)
        nf9_free_parse_result(pr);
    nf9_free_stats(stats);
    nf9_free(state);
}

TEST(PCAPTest, Malformed5Test)
{
    /* The PCAP contains a Netflow packet where one flowset has no
     * option fields and scope field with length equals zero.
     */
    nf9_state *state = nf9_init(0);
    std::vector<nf9_parse_result *> parse_result =
        parse_pcap(state, "testcases/malformed_5.pcap");

    const nf9_stats *stats = nf9_get_stats(state);

    EXPECT_EQ(nf9_get_stat(stats, NF9_STAT_MALFORMED_PACKETS), 0 /* 1 */);

    for (auto *pr : parse_result)
        nf9_free_parse_result(pr);
    nf9_free_stats(stats);
    nf9_free(state);
}

TEST(PCAPTest, TemplateMatchingTest)
{
    // Netflow::UniqueStreamID test_id_1 = {256, 104, "2.1.3.8"};
    // Netflow::UniqueStreamID test_id_2 = {257, 104, "172.17.0.5"};
    // Netflow::UniqueStreamID test_id_3 = {258, 104, "172.17.0.5"};

    // EXPECT_EQ(processor.template_library().count(), 4);
    // EXPECT_EQ(processor.template_library().exists(test_id_1), false);
    // EXPECT_EQ(processor.template_library().exists(test_id_2), true);
    // EXPECT_EQ(processor.template_library().exists(test_id_3), true);
}
