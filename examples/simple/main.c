#include <arpa/inet.h>
#include <errno.h>
#include <netflow9.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

/* ======================= libnetflow example =======================
 *
 * This example shows how you can use libnetflow to extract
 * information about IPv4 flows.
 *
 * The program receives UDP packets on port provided on the command
 * line, parses each packet, and for every flow inside the packet,
 * prints the number of bytes and the source and destination addresses.
 *
 * */

#define BUFSIZE 4096
#define MAX_MEM_USAGE (100 * 1000 * 1000)

const char *usage =
    "usage: %s PORT\n"
    "\n"
    "Arguments:\n"
    " PORT   port to listen on for netflow data\n";

struct flow
{
    struct in_addr src;
    struct in_addr dst;
    size_t bytes;
};

/* Parse a received packet and print info about the flows inside it. */
static void process_netflow_packet(nf9_state *parser, const uint8_t *buf,
                                   size_t size,
                                   const struct sockaddr_in *source);

/* Extract a flow from a parse result.  Returns 0 on success. */
static int extract_flow(struct flow *flow, const nf9_parse_result *pr,
                        unsigned flowset, unsigned flownum);

/* Print given flow to stdout. */
static void print_flow(const struct flow *flow);

int main(int argc, char **argv)
{
    uint16_t port;           /* port to listen on */
    int fd;                  /* socket fd */
    struct sockaddr_in addr; /* receiving socket address */
    struct sockaddr_in peer; /* who sent the packet */
    uint8_t buf[BUFSIZE];
    socklen_t addr_len;
    ssize_t len;
    nf9_state *parser;

    if (argc != 2) {
        fprintf(stderr, usage, argv[0]);
        exit(EXIT_FAILURE);
    }
    port = atoi(argv[1]);

    /* Create the UDP socket. */
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    if (!inet_aton("0.0.0.0", &addr.sin_addr)) {
        fprintf(stderr, "inet_aton failed\n");
        exit(EXIT_FAILURE);
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr))) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    /* Initialize the parser. */
    parser = nf9_init(0);

    /* Set maximum memory usage. */
    if (nf9_ctl(parser, NF9_OPT_MAX_MEM_USAGE, MAX_MEM_USAGE)) {
        fprintf(stderr, "nf9_ctl failed");
        exit(EXIT_FAILURE);
    }

    while (1) {
        addr_len = sizeof(peer);

        /* Receive the packet.
         *
         * We always need to have the source address, because the
         * library stores flow templates for each exporter device, and
         * the address identifies the device. */
        len =
            recvfrom(fd, buf, BUFSIZE, 0, (struct sockaddr *)&peer, &addr_len);

        if (len < 0) {
            perror("recvfrom");
            continue;
        }

        /* Parse the received packet. */
        process_netflow_packet(parser, buf, len, &peer);
    }
}

void process_netflow_packet(nf9_state *parser, const uint8_t *buf, size_t size,
                            const struct sockaddr_in *source)
{
    nf9_parse_result *parse_result;
    nf9_addr addr;
    size_t num_flowsets, num_flows;
    unsigned flowset, flownum;
    struct flow flow;

    /* nf9_addr stores the IP address of the device that generated the
     * Netflow packet.  */
    addr.family = AF_INET;
    addr.in = *source;

    /* Parse the packet. */
    if (nf9_parse(parser, &parse_result, buf, size, &addr)) {
        fprintf(stderr, "parsing error\n");
        return;
    }

    /* Now we iterate over every flow in the packet.
     *
     * In Netflow v9, a packet is made of 1 or more flowsets.  Each
     * flowset is either a data flowset, a template flowset or an
     * option flowset.  A data flowset may contain 0 or more flows.
     * The flows describe traffic between hosts.
     *
     * The other flowset types (template and options) are usually not
     * interesting to the library user - they are consumed by the
     * library though.
     * Template flowsets contain information how to decode data
     * flowsets.
     * Option flowsets contain meta-information about the flows in
     * data flowsets.
     *
     * */

    /* Iterate over every flowset. */
    num_flowsets = nf9_get_num_flowsets(parse_result);
    for (flowset = 0; flowset < num_flowsets; flowset++) {
        /* We are only interested in DATA flowsets. */
        if (nf9_get_flowset_type(parse_result, flowset) != NF9_FLOWSET_DATA)
            continue;

        num_flows = nf9_get_num_flows(parse_result, flowset);
        for (flownum = 0; flownum < num_flows; flownum++) {
            if (extract_flow(&flow, parse_result, flowset, flownum))
                continue;

            print_flow(&flow);
        }
    }

    /* Once we're done with the packet, we must free the parse result. */
    nf9_free_parse_result(parse_result);
}

int extract_flow(struct flow *flow, const nf9_parse_result *pr,
                 unsigned flowset, unsigned flownum)
{
    uint32_t sampling;
    size_t len;

    /* We need to extract these things from the parsed packet:
     *
     * - the source and destination addresses
     * - the number of bytes transferred
     *
     * Because routers typically only sample one out of every N
     * packets, we also need to extract the N to get the _approximate_
     * number of bytes.  In Netflow9, this is called 'sampling interval':
     *
     *   approx_in_bytes = IN_BYTES * SAMPLING_INTERVAL
     *
     * */

    /* Get the source address. */
    len = sizeof(flow->src);
    if (nf9_get_field(pr, flowset, flownum, NF9_FIELD_IPV4_SRC_ADDR, &flow->src,
                      &len))
        return 1;

    /* Get the destination address. */
    len = sizeof(flow->dst);
    if (nf9_get_field(pr, flowset, flownum, NF9_FIELD_IPV4_DST_ADDR, &flow->dst,
                      &len))
        return 1;

    /* Get the number of bytes. */
    len = sizeof(flow->bytes);
    if (nf9_get_field(pr, flowset, flownum, NF9_FIELD_IN_BYTES, &flow->bytes,
                      &len))
        return 1;

    /* And the multiplier for the number of bytes - which defaults to 1. */
    len = sizeof(sampling);
    if (!nf9_get_option(pr, NF9_FIELD_FLOW_SAMPLER_RANDOM_INTERVAL, &sampling,
                        &len))
        /* Netflow data is in network byte order. */
        sampling = ntohl(sampling);
    else
        sampling = 1;

    flow->bytes = ntohl(flow->bytes) * sampling;

    return 0;
}

void print_flow(const struct flow *flow)
{
    char srcaddrbuf[INET_ADDRSTRLEN], dstaddrbuf[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &flow->src, srcaddrbuf, sizeof(srcaddrbuf));
    inet_ntop(AF_INET, &flow->dst, dstaddrbuf, sizeof(dstaddrbuf));

    fprintf(stderr, "%9lu Bytes: %16s -> %16s\n", flow->bytes, srcaddrbuf,
            dstaddrbuf);
}
