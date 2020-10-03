import ipaddress
from libnetflow9 import LibNetflow9, NF9NotFoundError, NF9Opt
import argparse
import time
from enum import IntEnum
from scapy.all import (
    IP,
    UDP,
    NetflowHeader,
    NetflowHeaderV9,
    NetflowFlowsetV9,
    NetflowTemplateV9,
    NetflowTemplateFieldV9,
    GetNetflowRecordV9,
    NetflowDataflowsetV9
)


class ProtocolsIdentifier(IntEnum):
    ICMP = 1
    TCP = 6
    UDP = 17


class PacketCrafter:
    """
    Simple NetFlow packet crafting class
    """

    def __init__(self, ip_src_address, ip_dst_address):
        """
        Initialize packet crafter. Create headers and template.
        """
        self.header = IP(src=ip_src_address, dst=ip_dst_address) / UDP()
        self.netflow_header = NetflowHeader() / NetflowHeaderV9()
        self.flowset = NetflowFlowsetV9(
            templates=[NetflowTemplateV9(
                template_fields=[
                    NetflowTemplateFieldV9(fieldType=1, fieldLength=1),  # IN_BYTES
                    NetflowTemplateFieldV9(fieldType=2, fieldLength=4),  # IN_PKTS
                    NetflowTemplateFieldV9(fieldType=4),  # PROTOCOL
                    NetflowTemplateFieldV9(fieldType=8),  # IPV4_SRC_ADDR
                    NetflowTemplateFieldV9(fieldType=12),  # IPV4_DST_ADDR
                    NetflowTemplateFieldV9(fieldType=7),  # L4_SRC_PORT
                    NetflowTemplateFieldV9(fieldType=11),  # L4_DST_PORT
                    NetflowTemplateFieldV9(fieldType=6),  # TCP_FLAGS
                    NetflowTemplateFieldV9(fieldType=5),  # TOS
                ],
                templateID=256,
                fieldCount=9)
            ],
            flowSetID=0
        )
        self.recordClass = GetNetflowRecordV9(self.flowset)

    def craft_record(self, args):
        """
        Craft NetFlow v9 record
        """
        record = NetflowDataflowsetV9(
            templateID=256,
            records=[  # Some random data.
                self.recordClass(
                    IN_BYTES=b"\x12",
                    IN_PKTS=b"\0\0\0\0",
                    PROTOCOL=args.proto,
                    IPV4_SRC_ADDR=args.src_ip,
                    IPV4_DST_ADDR=args.dst_ip,
                    L4_SRC_PORT=args.src_port,
                    L4_DST_PORT=args.dst_port,
                    TCP_FLAGS=args.flags,
                    TOS=args.tos
                )
            ]
        )
        pkt = self.header / self.netflow_header / self.flowset / record
        return bytes(pkt[UDP].payload)


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", help="specify protocol", type=str, dest="proto",
                        default="udp")
    parser.add_argument("--src-port", help="specify source port", type=int, default=80)
    parser.add_argument("--dst-port", help="specify destination port", type=int, default=1000)
    parser.add_argument("--src-ip", help="specify source IP", type=str, default="192.168.0.10")
    parser.add_argument("--dst-ip", help="specify destination IP", type=str, default="192.168.0.11")
    parser.add_argument("-f", help="specify TCP flags", type=int, dest="flags", default=0)
    parser.add_argument("-t", help="specify value of ToS field", type=int, dest="tos", default=2)

    args = parser.parse_args()
    if args.proto in {"tcp", "TCP"}:
        args.proto = ProtocolsIdentifier.TCP
    elif args.proto in {"udp", "UDP"}:
        args.proto = ProtocolsIdentifier.UDP
    elif args.proto in {"icmp", "ICMP"}:
        args.proto = ProtocolsIdentifier.ICMP
    else:
        args.proto = int(args.proto)

    return args


def main():
    args = parse_arguments()

    # craft packet
    packet_crafter = PacketCrafter("127.0.0.1", "172.16.238.12")
    pkt = packet_crafter.craft_record(args)

    # create lib state
    nf9_lib = LibNetflow9()

    # decode crafted packet
    nf9_pkt = nf9_lib.decode(pkt)

    # get information from decoded packet
    print("timestamp:", nf9_pkt.get_timestamp())
    print("uptime:", nf9_pkt.get_uptime())

    # get number of flowsets from packet, in this example there should be two of them
    flowsets_nb = nf9_pkt.get_num_flowsets()
    print("flowsets:", flowsets_nb)
    assert flowsets_nb == 2

    # get types of flowsets and number of flows in flowsets
    for flowset in range(flowsets_nb):
        print(f"flowset {flowset + 1} type:", nf9_pkt.get_flowset_type(flowset))
        print(f"flowset {flowset + 1} number of flows:", nf9_pkt.get_num_flows(flowset))

    # first flowset represents the template, second represents the record that has one flow
    # get some values from first and only flow of second flowset
    second_flowset = 1
    first_flow = 0
    proto_field_nb = 4
    field_val = nf9_pkt.get_field(second_flowset, first_flow, proto_field_nb)
    print("proto:", int.from_bytes(field_val, "big"))
    src_ip_field_nb = 8
    field_val = nf9_pkt.get_field(second_flowset, first_flow, src_ip_field_nb)
    print("src IP:", ipaddress.ip_address(field_val))
    dst_ip_field_nb = 12
    field_val = nf9_pkt.get_field(second_flowset, first_flow, dst_ip_field_nb)
    print("dst IP:", ipaddress.ip_address(field_val))

    # get current stats
    print(nf9_lib.get_stats())

    # get all fields and values from first and only flow of second flowset
    fields = nf9_pkt.get_all_fields(second_flowset, first_flow)
    print(fields)

    # set max memory usage to 1000 bytes
    nf9_lib.ctl(NF9Opt.NF9_OPT_MAX_MEM_USAGE, 1000)

    # try to get sampling rate, and catch an exception, because sampling was not provided
    # in crafted packets
    try:
        sampling = nf9_pkt.get_sampling_rate(second_flowset, first_flow)
        print(sampling)
    except NF9NotFoundError:
        print("Sampling not provided")


if __name__ == '__main__':
    main()
