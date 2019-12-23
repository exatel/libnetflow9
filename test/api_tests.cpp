#include <gtest/gtest.h>
#include <netflow9.h>
#include <tins/tins.h>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include "test_common.h"

TEST_F(PCAPTest, foo)
{
    nf9_state* state = nf9_init(0);

    auto packets = get_packets("testcases/1.pcap");

    std::vector<int> parsed;

    for (const auto& packet : packets) {
        nf9_parse_result* result;
        if (nf9_parse(state, &result, packet.data, packet.len, &packet.peer,
                      packet.peer_len))
            continue;

        for (size_t flowset = 0; flowset < nf9_get_num_flowsets(result);
             flowset++)
            for (size_t flow = 0; flow < nf9_get_num_flows(result, flowset);
                 flow++) {
                nf9_value v = nf9_get_field(result, flowset, flow, NF9_FIELD_PACKETS);
                size_t n_packets = v.dword;

                parsed.push_back(n_packets);
            }

        nf9_free_parse_result(result);
    }

    // Netflow::UniqueStreamID test_id_1 = {256, 104, "2.1.3.8"};
    // Netflow::UniqueStreamID test_id_2 = {257, 104, "172.17.0.5"};
    // Netflow::UniqueStreamID test_id_3 = {258, 104, "172.17.0.5"};

    // EXPECT_EQ(processor.template_library().count(), 4);
    // EXPECT_EQ(processor.template_library().exists(test_id_1), false);
    // EXPECT_EQ(processor.template_library().exists(test_id_2), true);
    // EXPECT_EQ(processor.template_library().exists(test_id_3), true);

    nf9_free(state);
}

// TEST(NetflowTemplateLibrary, ExceptionIsThrownWhenWrongUniqueStreamID)
// {
//     Netflow::NetflowTemplateLibrary template_library;
//     EXPECT_THROW(template_library.get({100, 104, "172.17.0.5"}),
//                  Netflow::MissingTemplate);
// }

// TEST(NetflowTemplateLibrary, ReturnFalseWhenFlowsetDoesNotExist)
// {
//     Netflow::NetflowTemplateLibrary template_library;
//     EXPECT_FALSE(template_library.exists({100, 104, "172.17.0.5"}));
// }
