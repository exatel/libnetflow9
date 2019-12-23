#ifndef TEST_COMMON_H__
#define TEST_COMMON_H__
#include <netflow9/netflow9.h>
#include <tins/tins.h>
#include <functional>

class General : public testing::Test
{
public:
};

class PCAPTest : public General
{
public:
    struct Packet
    {
        const uint8_t *data;
        size_t len;
        sockaddr peer;
        socklen_t peer_len;
    };

    std::vector<Packet> get_packets(const char *pcap_path)
    {
        using namespace Tins;

        std::vector<Packet> ret;

        FileSniffer sniffer(pcap_path);
        for (const Tins::Packet &packet : sniffer) {
            const UDP *udp = packet.pdu()->find_pdu<UDP>();

            if (udp != nullptr) {
                const RawPDU &udp_payload = udp->rfind_pdu<RawPDU>();
                const uint8_t *contents = udp_payload.payload().data();
                const IP *ip = packet.pdu()->find_pdu<IP>();
                sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = uint32_t(ip->src_addr());
                addr.sin_port = udp->sport();

                if (contents != nullptr)
                    ret.emplace_back(
                        Packet{contents, udp_payload.payload().size(), 
                               *(sockaddr*)(&addr), sizeof(sockaddr_in)});
            }
        }

        return ret;
    }

private:
};

#endif
