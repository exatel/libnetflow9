/*
 * Copyright © 2019-2020 Exatel S.A.
 * Contact: opensource@exatel.pl
 * LICENSE: LGPL-3.0-or-later, See COPYING*.md files.
 */

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

class pcap_test : public test
{
protected:
    std::vector<packet> decode_pcap(std::string path)
    {
        auto packets = get_packets(path.c_str());
        std::vector<packet> decoded;

        for (const auto &packet : packets) {
            nf9_packet *result;
            if (nf9_decode(state_, &result, packet.data_.data(),
                           packet.data_.size(), &packet.addr))
                continue;
            decoded.emplace_back(result);
        }

        return decoded;
    }
};

TEST_F(pcap_test, basic_test)
{
    std::vector<packet> decoded_pcap = decode_pcap("testcases/1.pcap");

    std::vector<uint32_t> src_ips;
    for (const auto &pkt : decoded_pcap) {
        for (size_t flowset = 0; flowset < nf9_get_num_flowsets(pkt.get());
             ++flowset) {
            if (nf9_get_flowset_type(pkt.get(), flowset) != NF9_FLOWSET_DATA)
                continue;
            for (size_t flownum = 0;
                 flownum < nf9_get_num_flows(pkt.get(), flowset); ++flownum) {
                uint32_t src;
                size_t len = sizeof(uint32_t);
                if (nf9_get_field(pkt.get(), flowset, flownum,
                                  NF9_FIELD_IPV4_SRC_ADDR, &src, &len))
                    continue;

                src_ips.push_back(src);
            }
        }
    }

    ASSERT_EQ(src_ips.size(), 2);
    ASSERT_STREQ(inet_ntoa(in_addr{src_ips[0]}), "172.17.0.5");
    ASSERT_STREQ(inet_ntoa(in_addr{src_ips[1]}), "172.17.0.5");
}

TEST_F(pcap_test, basic_stats_test)
{
    std::vector<packet> pkt = decode_pcap("testcases/1.pcap");
    stats st = get_stats();

    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_TOTAL_RECORDS), 4);
    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_TOTAL_DATA_TEMPLATES), 2);
    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_TOTAL_OPTION_TEMPLATES), 2);
    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_MISSING_TEMPLATE_ERRORS), 0);
    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_MALFORMED_PACKETS), 0);
}

TEST_F(pcap_test, options_obtaining_test)
{
    std::vector<packet> decoded_pcap = decode_pcap("testcases/1.pcap");
    for (const auto &pkt : decoded_pcap) {
        for (size_t flowset = 0; flowset < nf9_get_num_flowsets(pkt.get());
             ++flowset) {
            if (nf9_get_flowset_type(pkt.get(), flowset) != NF9_FLOWSET_DATA)
                continue;
            for (size_t flownum = 0;
                 flownum < nf9_get_num_flows(pkt.get(), flowset); ++flownum) {
                uint32_t flows_exp;
                uint32_t pkt_exp;
                size_t len = sizeof(uint32_t);
                ASSERT_EQ(nf9_get_option(pkt.get(), NF9_FIELD_TOTAL_FLOWS_EXP,
                                         &flows_exp, &len),
                          0);
                ASSERT_EQ(ntohl(flows_exp), 1);
                ASSERT_EQ(nf9_get_option(pkt.get(), NF9_FIELD_TOTAL_PKTS_EXP,
                                         &pkt_exp, &len),
                          0);
                ASSERT_EQ(ntohl(pkt_exp), 20568);
            }
        }
    }
}

TEST_F(pcap_test, malformed_1_test)
{
    std::vector<packet> pkt = decode_pcap("testcases/malformed_1.pcap");
    stats st = get_stats();

    // This PCAP is malformed: it has empty data templates.
    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_MALFORMED_PACKETS), 3);
}

TEST_F(pcap_test, malformed_2_test)
{
    /*
     * This PCAP has 16 packets.  In each packet, there is a flowset that
     * has length equal to 1, which is invalid.  The minimum length of a
     * flowset is 4 bytes.
     */
    std::vector<packet> pkt = decode_pcap("testcases/malformed_2.pcap");
    stats st = get_stats();

    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_MALFORMED_PACKETS), 16);
}

TEST_F(pcap_test, malformed_3_test)
{
    /*
     * The PCAP contains a NetFlow packet where one option template
     * has option length equals zero.
     */
    std::vector<packet> pkt = decode_pcap("testcases/malformed_3.pcap");
    stats st = get_stats();

    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_MALFORMED_PACKETS), 1);
}

TEST_F(pcap_test, malformed_4_test)
{
    /*
     * The PCAP contains a NetFlow packet where one flowset
     * has length that equals zero.
     */
    std::vector<packet> pkt = decode_pcap("testcases/malformed_4.pcap");
    stats st = get_stats();

    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_MALFORMED_PACKETS), 1);
}

TEST_F(pcap_test, malformed_5_test)
{
    /*
     * The PCAP contains a NetFlow packet where one flowset has no
     * option fields and scope field with length equals zero.
     */
    std::vector<packet> pkt = decode_pcap("testcases/malformed_5.pcap");
    stats st = get_stats();

    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_MALFORMED_PACKETS), 1);
}

TEST_F(pcap_test, malformed_6_test)
{
    /*
     * The PCAP contains a NetFlow packet where first flowset contains
     * normal option template but second has length that is greater than
     * zero and less than 4 bytes.
     */
    std::vector<packet> pkt = decode_pcap("testcases/malformed_6.pcap");
    stats st = get_stats();

    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_MALFORMED_PACKETS), 1);
}
