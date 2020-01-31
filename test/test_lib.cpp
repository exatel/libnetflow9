/*
 * Copyright © 2019-2020 Exatel S.A.
 * Contact: github@exatel.pl
 * LICENSE: LGPL-3.0-or-later, See COPYING*.md files.
 */

#include "test_lib.h"

std::vector<pcap_packet> get_packets(const char *pcap_path)
{
    using namespace Tins;

    std::vector<pcap_packet> ret;

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
                ret.emplace_back(pcap_packet{udp_payload.payload(), addr});
        }
    }

    return ret;
}

nf9_addr make_inet_addr(const char *addr, uint16_t port)
{
    sockaddr_in in = {};
    in.sin_family = AF_INET;
    in.sin_port = port;
    in.sin_addr.s_addr = inet_addr(addr);

    nf9_addr a;
    a.in = in;
    return a;
}

nf9_addr make_inet6_addr(const char *addr, uint16_t port)
{
    sockaddr_in6 in = {};
    in.sin6_family = AF_INET6;
    in.sin6_port = port;
    if (!inet_pton(AF_INET6, addr, &in.sin6_addr))
        throw std::invalid_argument(
            std::string("IPv6 addres conversion error: ") + strerror(errno));

    nf9_addr a;
    a.in6 = in;
    return a;
}

std::string address_to_string(const nf9_addr &addr)
{
    if (addr.family == AF_INET) {
        char buf[INET_ADDRSTRLEN];
        if (!inet_ntop(addr.in.sin_family, &addr.in.sin_addr, buf, sizeof(buf)))
            throw std::runtime_error(std::string("address conversion error: ") +
                                     strerror(errno));
        return std::string(buf);
    }
    if (addr.family == AF_INET6) {
        char buf[INET6_ADDRSTRLEN];
        if (!inet_ntop(addr.in6.sin6_family, &addr.in6.sin6_addr, buf,
                       sizeof(buf)))
            throw std::runtime_error(std::string("address conversion error: ") +
                                     strerror(errno));
        return std::string(buf);
    }

    throw std::runtime_error("unsupported address family");
}
