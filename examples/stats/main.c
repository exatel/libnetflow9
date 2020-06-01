/*
 * Copyright © 2019-2020 Exatel S.A.
 * Contact: opensource@exatel.pl
 * LICENSE: LGPL-3.0-or-later, See COPYING*.md files.
 */

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
 * packets on a port given on command line.  It decodes the packets,
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

/* Decode a received packet. */
static void process(nf9_state *decoder, const uint8_t *buf, size_t size,
                    const struct sockaddr_in *source);

/* Print Netflow statistics: number of templates, option templates, etc. */
static void print_stats(const nf9_state *decoder);

int main(int argc, char **argv)
{
    uint16_t port;
    int fd;
    struct sockaddr_in addr;
    struct sockaddr_in peer;
    uint8_t buf[BUFSIZE];
    socklen_t addr_len;
    ssize_t len;
    nf9_state *decoder;
    struct timeval timeout; /* timeout for `recvfrom' */
    time_t last_print_time; /* when did we last print statistics */
    int err;

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

    /* Initialize the decoder. */
    decoder = nf9_init(0);

    /* Set maximum memory usage. */
    err = nf9_ctl(decoder, NF9_OPT_MAX_MEM_USAGE, MAX_MEM_USAGE);
    if (err != 0) {
        fprintf(stderr, "nf9_ctl: %s\n", nf9_strerror(err));
        exit(EXIT_FAILURE);
    }

    last_print_time = 0;

    while (1) {
        addr_len = sizeof(peer);

        if (time(NULL) > last_print_time) {
            print_stats(decoder);
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

        /* Decode the received packet. */
        process(decoder, buf, len, &peer);
    }
}

void process(nf9_state *decoder, const uint8_t *buf, size_t size,
             const struct sockaddr_in *source)
{
    nf9_packet *packet;
    nf9_addr addr;
    int err;

    addr.family = AF_INET;
    addr.in = *source;

    err = nf9_decode(decoder, &packet, buf, size, &addr);
    if (err != 0) {
        fprintf(stderr, "nf9_decode: %s\n", nf9_strerror(err));
        return;
    }

    nf9_free_packet(packet);
}

void print_stats(const nf9_state *decoder)
{
    const nf9_stats *stats;

    stats = nf9_get_stats(decoder);

    printf(
        "templates: %lu option templates: %lu data records: %lu mem usage: "
        "%lu\n",
        nf9_get_stat(stats, NF9_STAT_TOTAL_DATA_TEMPLATES),
        nf9_get_stat(stats, NF9_STAT_TOTAL_OPTION_TEMPLATES),
        nf9_get_stat(stats, NF9_STAT_TOTAL_RECORDS),
        nf9_get_stat(stats, NF9_STAT_MEMORY_USAGE));

    nf9_free_stats(stats);
}
