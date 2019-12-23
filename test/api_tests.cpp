#include <gtest/gtest.h>
#include <netflow9.h>
#include <tins/tins.h>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include "test_lib.h"

std::vector<nf9_parse_result *> parse_pcap(nf9_state* state, std::string path)
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

TEST(PCAPTest, basic_test)
{
    nf9_state* state = nf9_init(0);
    std::vector<nf9_parse_result *> parsed_pcap = parse_pcap(state, "testcases/1.pcap");
    std::vector<uint32_t> src_ips;
    for (const auto &parse_result : parsed_pcap) {
        for (size_t flowset = 0; flowset < nf9_get_num_flowsets(parse_result); ++flowset) {
            for (size_t flow = 0; flow < nf9_get_num_flows(parse_result, flowset); ++flow) {
                nf9_value field = nf9_get_field(parse_result, flowset, flow, NF9_FIELD_IPV4_SRC_ADDR);
                src_ips.push_back(field.u32);
            }
        }
        nf9_free_parse_result(parse_result);
    }

    EXPECT_EQ(src_ips.size(), 2);

    nf9_free(state);
}

TEST(PCAPTest, stats_test)
{
    // EXPECT_EQ(processor.stats().processed_flow_records, 4);
    // EXPECT_EQ(processor.stats().processed_template_records, 4);
    // EXPECT_EQ(processor.stats().processed_options_template_records, 2);
    // EXPECT_EQ(processor.stats().missing_template_errors, 0);
    // EXPECT_EQ(processor.stats().received_malformed_packets, 5);
    //     Netflow::NetflowProcessor processor;
    //     process_stream("testcases/Heap_Spray.pcapng", processor);
    //     EXPECT_EQ(processor.stats().received_malformed_packets, 3);
    //     process_stream("testcases/Heap_Spray_1.pcapng", processor);
    //     EXPECT_EQ(processor.stats().received_malformed_packets, 19);
    //     process_stream("testcases/super_.pcap", processor);
    //     EXPECT_EQ(processor.stats().received_malformed_packets, 20);
}

TEST(PCAPTest, tamplate_matching_test)
{
    // Netflow::UniqueStreamID test_id_1 = {256, 104, "2.1.3.8"};
    // Netflow::UniqueStreamID test_id_2 = {257, 104, "172.17.0.5"};
    // Netflow::UniqueStreamID test_id_3 = {258, 104, "172.17.0.5"};

    // EXPECT_EQ(processor.template_library().count(), 4);
    // EXPECT_EQ(processor.template_library().exists(test_id_1), false);
    // EXPECT_EQ(processor.template_library().exists(test_id_2), true);
    // EXPECT_EQ(processor.template_library().exists(test_id_3), true);
}