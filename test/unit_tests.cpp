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

TEST_F(test, returns_same_ipv4_address)
{
    std::vector<uint8_t> packet = netflow_packet_builder().build();
    nf9_addr addr = make_inet_addr("192.168.0.1");
    parse_result result = parse(packet.data(), packet.size(), &addr);

    nf9_addr returned_addr = nf9_get_addr(result.get());
    ASSERT_EQ(address_to_string(returned_addr), address_to_string(addr));
}

TEST_F(test, returns_same_ipv6_address)
{
    std::vector<uint8_t> packet = netflow_packet_builder().build();
    nf9_addr addr = make_inet6_addr("1:0:0:0:0:0:0:8");
    parse_result result = parse(packet.data(), packet.size(), &addr);

    nf9_addr returned_addr = nf9_get_addr(result.get());
    ASSERT_EQ(address_to_string(returned_addr), address_to_string(addr));
}

TEST_F(test, detects_missing_templates)
{
    std::vector<uint8_t> packet = netflow_packet_builder()
                                      .add_data_flowset(267)
                                      .add_data_field(uint32_t(12345))
                                      .build();

    nf9_addr addr = make_inet_addr("192.168.0.123");
    parse_result result = parse(packet.data(), packet.size(), &addr);

    stats st = get_stats();
    ASSERT_EQ(nf9_get_stat(st.get(), NF9_STAT_MISSING_TEMPLATE_ERRORS),
              0 /* 1 */);
}
