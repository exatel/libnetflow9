#include <arpa/inet.h>
#include <errno.h>
#include <netflow9.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

/* ======================= libnetflow example =======================
 *
 * This example shows how you can get statistics from libnetflow.
 *
 * Like the simple example program, this program listens for UDP
 * packets on a port given on command line.  It parses the packets,
 * and every second, prints the number of data templates, option
 * templates and flows that the library knows about.
 *
 * */

#define BUFSIZE 4096
#define MAX_MEM_USAGE (100 * 1000 * 1000)

const char *usage =
    "usage: %s PORT\n"
    "\n"
    "Arguments:\n"
    " PORT   port to listen on for netflow data\n";

/* Parse a received packet. */
static void process(nf9_state *parser, const uint8_t *buf, size_t size,
                    const struct sockaddr_in *source);

/* Print Netflow statistics: number of templates, option templates, etc. */
static void print_stats(const nf9_state *parser);

int main(int argc, char **argv)
{
    uint16_t port;
    int fd;
    struct sockaddr_in addr;
    struct sockaddr_in peer;
    uint8_t buf[BUFSIZE];
    socklen_t addr_len;
    ssize_t len;
    nf9_state *parser;
    struct timeval timeout; /* timeout for `recvfrom' */
    time_t last_print_time; /* when did we last print statistics */

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
    /* Set timeout. */
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) {
        perror("setsockopt");
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

    last_print_time = 0;

    while (1) {
        addr_len = sizeof(peer);

        if (time(NULL) > last_print_time) {
            print_stats(parser);
            last_print_time = time(NULL);
        }

        len =
            recvfrom(fd, buf, BUFSIZE, 0, (struct sockaddr *)&peer, &addr_len);

        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            perror("recvfrom");
            continue;
        }

        /* Parse the received packet. */
        process(parser, buf, len, &peer);
    }
}

void process(nf9_state *parser, const uint8_t *buf, size_t size,
             const struct sockaddr_in *source)
{
    nf9_parse_result *parse_result;
    nf9_addr addr;

    addr.family = AF_INET;
    addr.in = *source;

    if (nf9_parse(parser, &parse_result, buf, size, &addr)) {
        fprintf(stderr, "parsing error\n");
        return;
    }

    nf9_free_parse_result(parse_result);
}

void print_stats(const nf9_state *parser)
{
    const nf9_stats *stats;

    stats = nf9_get_stats(parser);

    printf(
        "templates: %lu option templates: %lu data records: %lu mem usage: "
        "%lu\n",
        nf9_get_stat(stats, NF9_STAT_TOTAL_DATA_TEMPLATES),
        nf9_get_stat(stats, NF9_STAT_TOTAL_OPTION_TEMPLATES),
        nf9_get_stat(stats, NF9_STAT_TOTAL_RECORDS),
        nf9_get_stat(stats, NF9_STAT_MEMORY_USAGE));

    nf9_free_stats(stats);
}
