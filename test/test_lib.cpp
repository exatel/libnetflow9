#include "test_lib.h"

std::vector<PCAPPacket> get_packets(const char *pcap_path)
{
    using namespace Tins;

    std::vector<PCAPPacket> ret;

    FileSniffer sniffer(pcap_path);
    for (const Tins::Packet &packet : sniffer) {
        const UDP *udp = packet.pdu()->find_pdu<UDP>();

        if (udp != nullptr) {
            const RawPDU &udp_payload = udp->rfind_pdu<RawPDU>();
            const uint8_t *contents = udp_payload.payload().data();
            const IP *ip = packet.pdu()->find_pdu<IP>();
            sockaddr_in in_addr;
            in_addr.sin_family = AF_INET;
            in_addr.sin_addr.s_addr = uint32_t(ip->src_addr());
            in_addr.sin_port = udp->sport();

            nf9_addr addr;
            addr.in = in_addr;

            if (contents != nullptr)
                ret.emplace_back(
                    PCAPPacket{contents, udp_payload.payload().size(), addr});
        }
    }

    return ret;
}
