#ifndef TYPES_H
#define TYPES_H

#include <netflow9.h>
#include <netinet/in.h>
#include <vector>

struct nf9_stats
{
    int processed_packets = 0;
    int malformed_packets = 0;
    int records = 0;
    int templates = 0;
    int option_templates = 0;
    int missing_template_errors = 0;
};

struct nf9_state
{
    int flags;
    nf9_stats stats;
};

struct flowset
{
    nf9_flowset_type type;
};

struct nf9_parse_result
{
    std::vector<flowset> flowsets;
    sockaddr addr;
};

#endif
