#ifndef NETFLOW9_H
#define NETFLOW9_H

#include <stddef.h>
#include <stdint.h>

#include <netinet/in.h>
#include <sys/socket.h>

#ifdef NF9_BUILD
#define NF9_API __attribute__((__visibility__("default")))
#else
#define NF9_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum nf9_state_flags {
    NF9_THREAD_SAFE = 1,
};
typedef struct nf9_state nf9_state;

NF9_API nf9_state* nf9_init(int flags);
NF9_API void nf9_free(nf9_state* state);

typedef struct nf9_parse_result nf9_parse_result;

typedef union nf9_addr {
    sa_family_t family;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
} nf9_addr;

NF9_API int nf9_parse(nf9_state* state, nf9_parse_result** result,
                      const uint8_t* buf, size_t len, const nf9_addr* addr);

NF9_API void nf9_free_parse_result(nf9_parse_result* result);

enum nf9_field {
    NF9_FIELD_F0,
    NF9_FIELD_IN_BYTES,
    NF9_FIELD_IN_PKTS,
    NF9_FIELD_FLOWS,
    NF9_FIELD_PROTOCOL,
    NF9_FIELD_TOS,
    NF9_FIELD_TCP_FLAGS,
    NF9_FIELD_L4_SRC_PORT,
    NF9_FIELD_IPV4_SRC_ADDR,
    NF9_FIELD_SRC_MASK,
    NF9_FIELD_INPUT_SNMP,
    NF9_FIELD_L4_DST_PORT,
    NF9_FIELD_IPV4_DST_ADDR,
    NF9_FIELD_DST_MASK,
    NF9_FIELD_OUTPUT_SNMP,
    NF9_FIELD_IPV4_NEXT_HOP,
    NF9_FIELD_SRC_AS,
    NF9_FIELD_DST_AS,
    NF9_FIELD_BGP_IPV4_NEXT_HOP,
    NF9_FIELD_MUL_DST_PKTS,
    NF9_FIELD_MUL_DST_BYTES,
    NF9_FIELD_LAST_SWITCHED,
    NF9_FIELD_FIRST_SWITCHED,
    NF9_FIELD_OUT_BYTES,
    NF9_FIELD_OUT_PKTS,
    NF9_FIELD_F25,
    NF9_FIELD_F26,
    NF9_FIELD_IPV6_SRC_ADDR,
    NF9_FIELD_IPV6_DST_ADDR,
    NF9_FIELD_IPV6_SRC_MASK,
    NF9_FIELD_IPV6_DST_MASK,
    NF9_FIELD_IPV6_FLOW_LABEL,
    NF9_FIELD_ICMP_TYPE,
    NF9_FIELD_MUL_IGMP_TYPE,
    NF9_FIELD_SAMPLING_INTERVAL,
    NF9_FIELD_SAMPLING_ALGORITHM,
    NF9_FIELD_FLOW_ACTIVE_TIMEOUT,
    NF9_FIELD_FLOW_INACTIVE_TIMEOUT,
    NF9_FIELD_ENGINE_TYPE,
    NF9_FIELD_ENGINE_ID,
    NF9_FIELD_TOTAL_BYTES_EXP,
    NF9_FIELD_TOTAL_PKTS_EXP,
    NF9_FIELD_TOTAL_FLOWS_EXP,
    NF9_FIELD_F43,
    NF9_FIELD_F44,
    NF9_FIELD_F45,
    NF9_FIELD_MPLS_TOP_LABEL_TYPE,
    NF9_FIELD_MPLS_TOP_LABEL_IP_ADDR,
    NF9_FIELD_FLOW_SAMPLER_ID,
    NF9_FIELD_FLOW_SAMPLER_MODE,
    NF9_FIELD_FLOW_SAMPLER_RANDOM_INTERVAL,
    NF9_FIELD_F51,
    NF9_FIELD_F52,
    NF9_FIELD_F53,
    NF9_FIELD_F54,
    NF9_FIELD_DST_TOS,
    NF9_FIELD_SRC_MAC,
    NF9_FIELD_DST_MAC,
    NF9_FIELD_SRC_VLAN,
    NF9_FIELD_DST_VLAN,
    NF9_FIELD_IP_PROTOCOL_VERSION,
    NF9_FIELD_DIRECTION,
    NF9_FIELD_IPV6_NEXT_HOP,
    NF9_FIELD_BGP_IPV6_NEXT_HOP,
    NF9_FIELD_IPV6_OPTION_HEADERS,
    NF9_FIELD_F65,
    NF9_FIELD_F66,
    NF9_FIELD_F67,
    NF9_FIELD_F68,
    NF9_FIELD_F69,
    NF9_FIELD_MPLS_LABEL_1,
    NF9_FIELD_MPLS_LABEL_2,
    NF9_FIELD_MPLS_LABEL_3,
    NF9_FIELD_MPLS_LABEL_4,
    NF9_FIELD_MPLS_LABEL_5,
    NF9_FIELD_MPLS_LABEL_6,
    NF9_FIELD_MPLS_LABEL_7,
    NF9_FIELD_MPLS_LABEL_8,
    NF9_FIELD_MPLS_LABEL_9,
    NF9_FIELD_MPLS_LABEL_10,
    NF9_FIELD_IN_DST_MAC,
    NF9_FIELD_OUT_SRC_MAC,
    NF9_FIELD_IF_NAME,
    NF9_FIELD_IF_DESC,
    NF9_FIELD_SAMPLER_NAME,
    NF9_FIELD_IN_PERMANENT_BYTES,
    NF9_FIELD_IN_PERMANENT_PKTS,
    NF9_FIELD_F87,
    NF9_FIELD_FRAGMENT_OFFSET,
    NF9_FIELD_FORWARDING_STATUS,
    NF9_FIELD_MPLS_PAL_RD,
    NF9_FIELD_MPLS_PREFIX_LEN,
    NF9_FIELD_SRC_TRAFFIC_INDEX,
    NF9_FIELD_DST_TRAFFIC_INDEX,
    NF9_FIELD_APPLICATION_DESCRIPTION,
    NF9_FIELD_APPLICATION_TAG,
    NF9_FIELD_APPLICATION_NAME,
    NF9_FIELD_F97,
    NF9_FIELD_postipDiffServCodePoint,
    NF9_FIELD_replication_factor,
    NF9_FIELD_DEPRECATED,
    NF9_FIELD_F101,
    NF9_FIELD_layer2packetSectionOffset,
    NF9_FIELD_layer2packetSectionSize,
    NF9_FIELD_layer2packetSectionData,
    NF9_FIELD_F105,
    NF9_FIELD_F106,
    NF9_FIELD_F107,
    NF9_FIELD_F108,
    NF9_FIELD_F109,
    NF9_FIELD_F110,
    NF9_FIELD_F111,
    NF9_FIELD_F112,
    NF9_FIELD_F113,
    NF9_FIELD_F114,
    NF9_FIELD_F115,
    NF9_FIELD_F116,
    NF9_FIELD_F117,
    NF9_FIELD_F118,
    NF9_FIELD_F119,
    NF9_FIELD_F120,
    NF9_FIELD_F121,
    NF9_FIELD_F122,
    NF9_FIELD_F123,
    NF9_FIELD_F124,
    NF9_FIELD_F125,
    NF9_FIELD_F126,
    NF9_FIELD_F127,
    NF9_FIELD_F128,
    NF9_FIELD_F129,
    NF9_FIELD_F130,
    NF9_FIELD_F131,
    NF9_FIELD_F132,
    NF9_FIELD_F133,
    NF9_FIELD_F134,
    NF9_FIELD_F135,
    NF9_FIELD_F136,
    NF9_FIELD_F137,
    NF9_FIELD_F138,
    NF9_FIELD_F139,
    NF9_FIELD_F140,
    NF9_FIELD_F141,
    NF9_FIELD_F142,
    NF9_FIELD_F143,
    NF9_FIELD_F144,
    NF9_FIELD_F145,
    NF9_FIELD_F146,
    NF9_FIELD_F147,
    NF9_FIELD_F148,
    NF9_FIELD_F149,
    NF9_FIELD_F150,
    NF9_FIELD_F151,
    NF9_FIELD_F152,
    NF9_FIELD_F153,
    NF9_FIELD_F154,
    NF9_FIELD_F155,
    NF9_FIELD_F156,
    NF9_FIELD_F157,
    NF9_FIELD_F158,
    NF9_FIELD_F159,
    NF9_FIELD_F160,
    NF9_FIELD_F161,
    NF9_FIELD_F162,
    NF9_FIELD_F163,
    NF9_FIELD_F164,
    NF9_FIELD_F165,
    NF9_FIELD_F166,
    NF9_FIELD_F167,
    NF9_FIELD_F168,
    NF9_FIELD_F169,
    NF9_FIELD_F170,
    NF9_FIELD_F171,
    NF9_FIELD_F172,
    NF9_FIELD_F173,
    NF9_FIELD_F174,
    NF9_FIELD_F175,
    NF9_FIELD_F176,
    NF9_FIELD_F177,
    NF9_FIELD_F178,
    NF9_FIELD_F179,
    NF9_FIELD_F180,
    NF9_FIELD_F181,
    NF9_FIELD_F182,
    NF9_FIELD_F183,
    NF9_FIELD_F184,
    NF9_FIELD_F185,
    NF9_FIELD_F186,
    NF9_FIELD_F187,
    NF9_FIELD_F188,
    NF9_FIELD_F189,
    NF9_FIELD_F190,
    NF9_FIELD_F191,
    NF9_FIELD_F192,
    NF9_FIELD_F193,
    NF9_FIELD_F194,
    NF9_FIELD_F195,
    NF9_FIELD_F196,
    NF9_FIELD_F197,
    NF9_FIELD_F198,
    NF9_FIELD_F199,
    NF9_FIELD_F200,
    NF9_FIELD_F201,
    NF9_FIELD_F202,
    NF9_FIELD_F203,
    NF9_FIELD_F204,
    NF9_FIELD_F205,
    NF9_FIELD_F206,
    NF9_FIELD_F207,
    NF9_FIELD_F208,
    NF9_FIELD_F209,
    NF9_FIELD_F210,
    NF9_FIELD_F211,
    NF9_FIELD_F212,
    NF9_FIELD_F213,
    NF9_FIELD_F214,
    NF9_FIELD_F215,
    NF9_FIELD_F216,
    NF9_FIELD_F217,
    NF9_FIELD_F218,
    NF9_FIELD_F219,
    NF9_FIELD_F220,
    NF9_FIELD_F221,
    NF9_FIELD_F222,
    NF9_FIELD_F223,
    NF9_FIELD_F224,
    NF9_FIELD_F225,
    NF9_FIELD_F226,
    NF9_FIELD_F227,
    NF9_FIELD_F228,
    NF9_FIELD_F229,
    NF9_FIELD_F230,
    NF9_FIELD_F231,
    NF9_FIELD_F232,
    NF9_FIELD_F233,
    NF9_FIELD_Ingress_VRFID,
    NF9_FIELD_Egress_VRFID,
};

union nf9_value {
    uint32_t u32;
    uint64_t u64;
    struct
    {
        uint64_t upper;
        uint64_t lower;
    } u128;
    struct
    {
        size_t length;
        const void* bytes;
    } data;
};

NF9_API size_t nf9_get_num_flowsets(const nf9_parse_result* pr);

enum nf9_flowset_type {
    NF9_FLOWSET_TEMPLATE,
    NF9_FLOWSET_OPTIONS,
    NF9_FLOWSET_DATA,
};

NF9_API int nf9_get_flowset_type(const nf9_parse_result* pr, int flowset);

NF9_API size_t nf9_get_num_flows(const nf9_parse_result* pr, int flowset);
NF9_API nf9_value nf9_get_field(const nf9_parse_result* pr, int flowset,
                                int flow, int field);

NF9_API nf9_addr nf9_get_addr(const nf9_parse_result* pr);

enum nf9_stat_fields {
    NF9_STAT_PROCESSED_PACKETS,
    NF9_STAT_MALFORMED_PACKETS,
    NF9_STAT_TOTAL_RECORDS,
    NF9_STAT_TOTAL_TEMPLATES,
    NF9_STAT_TOTAL_OPTION_TEMPLATES,
    NF9_STAT_MISSING_TEMPLATE_ERRORS,
};

typedef struct nf9_stats nf9_stats;
NF9_API const nf9_stats* nf9_get_stats(const nf9_state* state);
NF9_API int nf9_get_stat(const nf9_stats* stats, int stat);
NF9_API void nf9_free_stats(const nf9_stats*);

#ifdef __cplusplus
}
#endif

#endif  // NETFLOW9_H
