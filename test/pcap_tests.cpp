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
    std::vector<parse_result> parse_pcap(std::string path)
    {
        auto packets = get_packets(path.c_str());
        std::vector<parse_result> parsed;

        for (const auto &packet : packets) {
            nf9_parse_result *result;
            if (nf9_parse(state_, &result, packet.data_.data(),
                          packet.data_.size(), &packet.addr))
                continue;
            parsed.emplace_back(result);
        }

        return parsed;
    }
};

TEST_F(pcap_test, basic_test)
{
    std::vector<parse_result> parsed_pcap = parse_pcap("testcases/1.pcap");
    nf9_addr addr = nf9_get_addr(parsed_pcap.at(0).get());
    EXPECT_EQ(addr.in.sin_addr.s_addr, inet_addr("172.17.0.5"));

    std::vector<uint32_t> src_ips;
    for (const auto &pr : parsed_pcap) {
        for (size_t flowset = 0; flowset < nf9_get_num_flowsets(pr.get());
             ++flowset) {
            for (size_t flownum = 0;
                 flownum < nf9_get_num_flows(pr.get(), flowset); ++flownum) {
                nf9_value field = nf9_get_field(pr.get(), flowset, flownum,
                                                NF9_FIELD_IPV4_SRC_ADDR);
                src_ips.push_back(field.u32);
            }
        }
    }

    ASSERT_EQ(src_ips.size(), 2);
    ASSERT_STREQ(inet_ntoa(in_addr{src_ips[0]}), "172.17.0.5");
    ASSERT_STREQ(inet_ntoa(in_addr{src_ips[1]}), "172.17.0.5");
}

TEST_F(pcap_test, basic_stats_test)
{
    std::vector<parse_result> pr = parse_pcap("testcases/1.pcap");
    stats st = get_stats();

    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_TOTAL_RECORDS), 4);
    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_TOTAL_TEMPLATES), 2);
    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_TOTAL_OPTION_TEMPLATES), 2);
    // FIXME: There are no missing templates here, but we don't have option
    // record parsing yet.  There are 2 option records in this PCAP.
    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_MISSING_TEMPLATE_ERRORS),
              2 /* 0 */);
    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_MALFORMED_PACKETS), 0);
}

TEST_F(pcap_test, malformed_1_test)
{
    std::vector<parse_result> pr = parse_pcap("testcases/malformed_1.pcap");
    stats st = get_stats();

    // This PCAP is malformed: it has empty data templates.
    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_MALFORMED_PACKETS), 3);
}

TEST_F(pcap_test, malformed_2_test)
{
    std::vector<parse_result> pr = parse_pcap("testcases/malformed_2.pcap");
    stats st = get_stats();

    // This PCAP has 16 packets.  In each packet, there is a flowset that has
    // length equal to 1, which is invalid.  The minimum length of a flowset is
    // 4 bytes.
    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_MALFORMED_PACKETS), 16);
}

TEST_F(pcap_test, malformed_3_test)
{
    // FIXME: Why is this PCAP malformed?  It looks correct, except for the fact
    // that template definitions are missing.
    std::vector<parse_result> pr = parse_pcap("testcases/malformed_3.pcap");
    stats st = get_stats();

    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_MALFORMED_PACKETS), 0 /* 20 */);
}

TEST_F(pcap_test, malformed_4_test)
{
    /* The PCAP contains a Netflow packet where one flowset
     * has length that equals zero.
     */
    std::vector<parse_result> pr = parse_pcap("testcases/malformed_4.pcap");
    stats st = get_stats();

    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_MALFORMED_PACKETS), 1);
}

TEST_F(pcap_test, malformed_5_test)
{
    /* The PCAP contains a Netflow packet where one flowset has no
     * option fields and scope field with length equals zero.
     */
    std::vector<parse_result> pr = parse_pcap("testcases/malformed_5.pcap");
    stats st = get_stats();

    // FIXME: Actually, it's not malformed.  A data record is missing a template
    // in this test.
    EXPECT_EQ(nf9_get_stat(st.get(), NF9_STAT_MALFORMED_PACKETS), 1);
}
