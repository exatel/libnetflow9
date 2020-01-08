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

TEST_F(test, templates_exceptions)
{
    const int bad_flowset_id = 1000, bad_template_id = 200;
    ASSERT_THROW(
        netflow_packet_builder().add_data_template(bad_template_id).build(),
        std::invalid_argument);
    ASSERT_THROW(
        netflow_packet_builder().add_data_template_flowset(bad_flowset_id),
        std::invalid_argument);
    ASSERT_THROW(
        netflow_packet_builder().add_data_template(bad_flowset_id).build(),
        std::runtime_error);
}

TEST_F(test, add_option_template_data)
{
    const int template_id = 1000;
    const int NF9_SCOPE_FIELD_SYSTEM =
        1;  // temporary value because there is no enum for option scope fields
    std::vector<uint8_t> packet;
    packet = netflow_packet_builder()
                 .add_option_template_flowset(template_id)
                 .add_option_scope_field(NF9_SCOPE_FIELD_SYSTEM, 4)
                 .add_option_field(NF9_FIELD_Ingress_VRFID, 4)
                 .build();
    nf9_addr addr = make_inet_addr("192.192.192.193");
    parse_result result = parse(packet.data(), packet.size(), &addr);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(nf9_get_num_flowsets(result.get()), 1);
    ASSERT_EQ(nf9_get_flowset_type(result.get(), 0), NF9_FLOWSET_OPTIONS);

    // decode data with option template
    packet = netflow_packet_builder()
                 .add_data_flowset(template_id)
                 .add_data_field(uint32_t(1000000))
                 .add_data_field(uint32_t(2000000))
                 .build();
    result = parse(packet.data(), packet.size(), &addr);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(nf9_get_num_flowsets(result.get()), 1);
    ASSERT_EQ(nf9_get_num_flows(result.get(), 0), 0 /* 1 */);

    // TODO: Uncomment when option parsing is implemented
    // nf9_value system =
    //     nf9_get_field(result.get(), 0, 0, NF9_SCOPE_FIELD_SYSTEM);
    // nf9_value vrf = nf9_get_field(result.get(), 0, 0,
    // NF9_FIELD_Ingress_VRFID); ASSERT_EQ(system.u32, 1000000);
    // ASSERT_EQ(vrf.u32, 2000000);
}

TEST_F(test, packet_too_short)
{
    nf9_addr addr = make_inet_addr("192.168.0.1");
    std::vector<uint8_t> packet = netflow_packet_builder().build();

    parse_result result = parse(packet.data(), packet.size() - 1, &addr);
    ASSERT_EQ(result, nullptr);
}

TEST_F(test, invalid_netflow_version)
{
    nf9_addr addr = make_inet_addr("192.168.0.1");
    netflow_header hdr{};
    hdr.version = htons(5);  // Invalid version.  We only support version 9.

    std::vector<uint8_t> packet(sizeof(hdr));
    memcpy(packet.data(), &hdr, sizeof(hdr));

    parse_result result = parse(packet.data(), packet.size(), &addr);
    ASSERT_EQ(result, nullptr);
}

TEST_F(test, flowset_too_short)
{
    nf9_addr addr = make_inet_addr("192.168.0.1");
    std::vector<uint8_t> packet = netflow_packet_builder().build();

    uint16_t& count = *reinterpret_cast<uint16_t*>(packet.data() + 2);
    count = ntohs(30);

    packet.resize(packet.size() + 3);

    parse_result result = parse(packet.data(), packet.size(), &addr);
    ASSERT_EQ(result, nullptr);
}

TEST_F(test, flowset_length_too_small)
{
    nf9_addr addr = make_inet_addr("192.168.0.1");
    std::vector<uint8_t> packet = netflow_packet_builder()
                                      .add_data_flowset(267)
                                      .add_data_field(uint32_t(12345))
                                      .build();

    uint16_t& first_flowset_length = *reinterpret_cast<uint16_t*>(
        packet.data() + sizeof(netflow_header) + sizeof(uint16_t));
    first_flowset_length = htons(2);

    parse_result result = parse(packet.data(), packet.size(), &addr);
    ASSERT_EQ(result, nullptr);
}

TEST_F(test, flowset_length_too_big)
{
    nf9_addr addr = make_inet_addr("192.168.0.1");
    std::vector<uint8_t> packet = netflow_packet_builder()
                                      .add_data_flowset(267)
                                      .add_data_field(uint32_t(12345))
                                      .build();

    uint16_t& first_flowset_length = *reinterpret_cast<uint16_t*>(
        packet.data() + sizeof(netflow_header) + sizeof(uint16_t));
    first_flowset_length = htons(128);

    parse_result result = parse(packet.data(), packet.size(), &addr);
    ASSERT_EQ(result, nullptr);
}

TEST_F(test, detects_missing_templates)
{
    std::vector<uint8_t> packet = netflow_packet_builder()
                                      .add_data_flowset(267)
                                      .add_data_field(uint32_t(12345))
                                      .build();

    nf9_addr addr = make_inet_addr("192.168.0.123");
    parse_result result = parse(packet.data(), packet.size(), &addr);
    ASSERT_NE(result, nullptr);

    stats st = get_stats();
    ASSERT_EQ(nf9_get_num_flowsets(result.get()), 1);
    ASSERT_EQ(nf9_get_stat(st.get(), NF9_STAT_MISSING_TEMPLATE_ERRORS), 1);
}

TEST_F(test, recognizes_template_flowsets)
{
    std::vector<uint8_t> packet =
        netflow_packet_builder()
            .add_data_template_flowset(200)
            .add_data_template(400)
            .add_data_template_field(NF9_FIELD_IPV4_DST_ADDR, 4)
            .build();

    nf9_addr addr = make_inet_addr("192.168.0.123");
    parse_result result = parse(packet.data(), packet.size(), &addr);

    ASSERT_NE(result, nullptr);
    ASSERT_EQ(nf9_get_num_flowsets(result.get()), 1);
    ASSERT_EQ(nf9_get_flowset_type(result.get(), 0), NF9_FLOWSET_TEMPLATE);
}

TEST_F(test, recognizes_data_flowsets)
{
    std::vector<uint8_t> packet =
        netflow_packet_builder().add_data_flowset(444).build();

    nf9_addr addr = make_inet_addr("192.168.0.123");
    parse_result result = parse(packet.data(), packet.size(), &addr);
    ASSERT_NE(result, nullptr);

    ASSERT_EQ(nf9_get_num_flowsets(result.get()), 1);
    ASSERT_EQ(nf9_get_flowset_type(result.get(), 0), NF9_FLOWSET_DATA);
}

TEST_F(test, recognizes_option_flowsets)
{
    std::vector<uint8_t> packet =
        netflow_packet_builder().add_option_template_flowset(900).build();

    nf9_addr addr = make_inet_addr("192.168.0.123");
    parse_result result = parse(packet.data(), packet.size(), &addr);
    ASSERT_NE(result, nullptr);

    ASSERT_EQ(nf9_get_num_flowsets(result.get()), 1);
    ASSERT_EQ(nf9_get_flowset_type(result.get(), 0), NF9_FLOWSET_OPTIONS);
}

TEST_F(test, parsing_data_flowset_from_template)
{
    nf9_addr addr = make_inet_addr("192.168.0.123");
    std::vector<uint8_t> packet;
    parse_result result;

    // First, feed data template to the parser
    packet = netflow_packet_builder()
                 .add_data_template_flowset(0)
                 .add_data_template(256)
                 .add_data_template_field(NF9_FIELD_IPV4_SRC_ADDR, 4)
                 .add_data_template_field(NF9_FIELD_IPV4_DST_ADDR, 4)
                 .build();
    result = parse(packet.data(), packet.size(), &addr);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(nf9_get_num_flowsets(result.get()), 1);
    ASSERT_EQ(nf9_get_flowset_type(result.get(), 0), NF9_FLOWSET_TEMPLATE);

    // Now, attempt to parse data flowset in previous template format.
    packet = netflow_packet_builder()
                 .add_data_flowset(256)
                 .add_data_field(uint32_t(875770417))  // SRC = 1.2.3.4
                 .add_data_field(uint32_t(943142453))  // DST = 5.6.7.8
                 .build();
    result = parse(packet.data(), packet.size(), &addr);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(nf9_get_num_flowsets(result.get()), 1);
    ASSERT_EQ(nf9_get_num_flows(result.get(), 0), 1);
    ASSERT_EQ(nf9_get_flowset_type(result.get(), 0), NF9_FLOWSET_DATA);

    nf9_value src = nf9_get_field(result.get(), 0, 0, NF9_FIELD_IPV4_SRC_ADDR);
    nf9_value dst = nf9_get_field(result.get(), 0, 0, NF9_FIELD_IPV4_DST_ADDR);
    ASSERT_EQ(src.u32, 875770417);
    ASSERT_EQ(dst.u32, 943142453);
}

TEST_F(test, data_record_underflow)
{
    nf9_addr addr = make_inet_addr("192.168.0.123");
    std::vector<uint8_t> packet;
    parse_result result;

    // Feed some template to the parser.
    packet = netflow_packet_builder()
                 .add_data_template_flowset(0)
                 .add_data_template(256)
                 .add_data_template_field(NF9_FIELD_IPV4_SRC_ADDR, 4)
                 .add_data_template_field(NF9_FIELD_IPV4_DST_ADDR, 4)
                 .build();
    result = parse(packet.data(), packet.size(), &addr);

    // Attempt to parse some data record. Notice: there's only one field here,
    // but the template defines two.
    packet = netflow_packet_builder()
                 .add_data_flowset(256)
                 .add_data_field(0)
                 .build();
    result = parse(packet.data(), packet.size(), &addr);
    ASSERT_NE(result, nullptr);

    // The packet shouldn't be treated as a valid flow.
    ASSERT_EQ(nf9_get_num_flows(result.get(), 0), 0);
}

TEST_F(test, multiple_data_templates)
{
    std::vector<uint8_t> packet =
        netflow_packet_builder()
            .add_data_template_flowset(200)
            .add_data_template(400)
            .add_data_template_field(NF9_FIELD_IPV4_SRC_ADDR, 4)
            .add_data_template(401)
            .add_data_template_field(NF9_FIELD_IPV4_DST_ADDR, 4)
            .build();

    nf9_addr addr = make_inet_addr("192.168.0.123");
    parse_result result = parse(packet.data(), packet.size(), &addr);

    ASSERT_NE(result, nullptr);

    EXPECT_EQ(state_->templates.size(), 2);
}

TEST_F(test, matching_template_per_address)
{
    nf9_addr addr1 = make_inet_addr("192.168.0.123");
    nf9_addr addr2 = make_inet_addr("169.254.0.1");
    std::vector<uint8_t> packet;
    parse_result result;

    // Feed data template to the parser using the first address.
    packet = netflow_packet_builder()
                 .add_data_template_flowset(0)
                 .add_data_template(256)
                 .add_data_template_field(NF9_FIELD_IPV4_SRC_ADDR, 4)
                 .add_data_template_field(NF9_FIELD_IPV4_DST_ADDR, 4)
                 .build();
    result = parse(packet.data(), packet.size(), &addr1);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(nf9_get_num_flowsets(result.get()), 1);
    ASSERT_EQ(nf9_get_flowset_type(result.get(), 0), NF9_FLOWSET_TEMPLATE);

    // Attempt to parse data using a template with the same id, but using the
    // second address.  This should fail, since templates are per (address,
    // source_id) pair.
    packet = netflow_packet_builder()
                 .add_data_flowset(256)
                 .add_data_field(uint32_t(0))
                 .add_data_field(uint32_t(0))
                 .build();
    result = parse(packet.data(), packet.size(), &addr2);

    // There should be one template matching error.
    stats st = get_stats();
    ASSERT_EQ(nf9_get_stat(st.get(), NF9_STAT_MISSING_TEMPLATE_ERRORS), 1);
}

TEST_F(test, matching_template_per_source_id)
{
    nf9_addr addr = make_inet_addr("192.168.0.123");
    std::vector<uint8_t> packet;
    parse_result result;

    packet = netflow_packet_builder()
                 .set_source_id(123)
                 .add_data_template_flowset(0)
                 .add_data_template(256)
                 .add_data_template_field(NF9_FIELD_IPV4_SRC_ADDR, 4)
                 .add_data_template_field(NF9_FIELD_IPV4_DST_ADDR, 4)
                 .build();
    result = parse(packet.data(), packet.size(), &addr);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(nf9_get_num_flowsets(result.get()), 1);
    ASSERT_EQ(nf9_get_flowset_type(result.get(), 0), NF9_FLOWSET_TEMPLATE);

    // The template id and source IP address are the same, but source id is
    // different here.
    packet = netflow_packet_builder()
                 .set_source_id(999)
                 .add_data_flowset(256)
                 .add_data_field(uint32_t(0))
                 .add_data_field(uint32_t(0))
                 .build();
    result = parse(packet.data(), packet.size(), &addr);

    stats st = get_stats();
    ASSERT_EQ(nf9_get_stat(st.get(), NF9_STAT_MISSING_TEMPLATE_ERRORS), 1);
}

TEST_F(test, detects_too_large_field_length_in_data_flowset)
{
    nf9_addr addr = make_inet_addr("192.168.0.123");
    std::vector<uint8_t> packet;
    parse_result result;

    // Feed a template with a large field.
    packet = netflow_packet_builder()
                 .add_data_template_flowset(0)
                 .add_data_template(400)
                 .add_data_template_field(NF9_FIELD_IPV6_DST_ADDR, 16)
                 .build();
    result = parse(packet.data(), packet.size(), &addr);
    ASSERT_NE(result, nullptr);

    // Attempt to parse a data record with a field whose length is shorter than
    // the length declared in template.
    packet = netflow_packet_builder()
                 .add_data_flowset(400)
                 .add_data_field(uint32_t(123))
                 .build();
    result = parse(packet.data(), packet.size(), &addr);
    ASSERT_NE(result, nullptr);

    ASSERT_EQ(nf9_get_num_flowsets(result.get()), 1);
    ASSERT_EQ(nf9_get_num_flows(result.get(), 0), 0);
}

TEST_F(test, template_with_zero_length_field)
{
    nf9_addr addr = make_inet_addr("192.168.0.123");
    std::vector<uint8_t> packet;
    parse_result result;

    // Feed a template with a field whose length is 0.
    packet = netflow_packet_builder()
                 .add_data_template_flowset(0)
                 .add_data_template(400)
                 .add_data_template_field(NF9_FIELD_INPUT_SNMP, 0)
                 .build();
    result = parse(packet.data(), packet.size(), &addr);
    ASSERT_EQ(result, nullptr);
}

TEST_F(test, empty_template)
{
    nf9_addr addr = make_inet_addr("192.168.0.123");
    std::vector<uint8_t> packet;
    parse_result result;

    packet = netflow_packet_builder()
                 .add_data_template_flowset(0)
                 .add_data_template(400)
                 .build();
    result = parse(packet.data(), packet.size(), &addr);
    ASSERT_EQ(result, nullptr);
}
