/*
 * Copyright © 2019-2020 Exatel S.A.
 * Contact: opensource@exatel.pl
 * LICENSE: LGPL-3.0-or-later, See COPYING*.md files.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

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

typedef uint32_t nf9_field;

#ifdef __cplusplus
#define NF9_DATA_FIELD(value) (static_cast<nf9_field>(value))
#define NF9_SCOPE_FIELD(value) (static_cast<nf9_field>(value | (1 << 31)))
#else
#define NF9_DATA_FIELD(value) ((nf9_field)value)
#define NF9_SCOPE_FIELD(value) ((nf9_field)(value | (1 << 31)))
#endif

/**
 * @brief Error codes used in libnetflow.
 */
enum nf9_error {
    NF9_ERR_INVALID_ARGUMENT = 1,

    NF9_ERR_NOT_FOUND,

    NF9_ERR_OUT_OF_MEMORY,

    NF9_ERR_MALFORMED,

    NF9_ERR_OUTDATED,
};

/**
 * @brief More info about sampling obtaining methods and errors
 */
enum nf9_sampling_info {
    /**
     * Sampling from option template matched with data record by IP address,
     * Source ID and Sampler ID. It's matching opion recommended by Cisco.
     */
    NF9_SAMPLING_MATCH_IP_SOURCE_ID_SAMPLER_ID = 1,

    /**
     * Sampling from option template matched with data record by IP address,
     * and Sampler ID. It is used when Source IDs are different.
     */
    NF9_SAMPLING_MATCH_IP_SAMPLER_ID = 2,

    /**
     * Sampler ID not found in data record
     */
    NF9_SAMPLING_SAMPLER_ID_NOT_FOUND = 3,

    /**
     * No matching option template has been found
     */
    NF9_SAMPLING_OPTION_RECORD_NOT_FOUND = 4,
};

/**
 * @brief Flags controlling behavior of a NetFlow decoder.
 *
 * These are static decoder settings, they can only be set in the
 * initializer.
 */
enum nf9_state_flag {
    _NF9_THREAD_SAFE = 1 /**< Reserved; don't use.  */,

    /**
     * If this flag is present, sampling rates are cached and can be retrieved
     * with nf9_get_sampling_rate().
     */
    NF9_STORE_SAMPLING_RATES = 2,
};

/**
 * @brief Type of a NetFlow flowset.
 */
enum nf9_flowset_type {
    NF9_FLOWSET_TEMPLATE,
    NF9_FLOWSET_OPTIONS,
    NF9_FLOWSET_DATA,
};

/**
 * @brief Statistics of a NetFlow decoder.
 */
enum nf9_stat {

    /**
     * Total number of processed packets.
     */
    NF9_STAT_PROCESSED_PACKETS,

    /**
     * Number of packets that were malformed.
     */
    NF9_STAT_MALFORMED_PACKETS,

    /**
     * Number of all DATA flowsets.
     */
    NF9_STAT_TOTAL_RECORDS,

    /**
     * Number of all data template flowsets.
     */
    NF9_STAT_TOTAL_DATA_TEMPLATES,

    /**
     * Number of all option template flowsets.
     */
    NF9_STAT_TOTAL_OPTION_TEMPLATES,

    /**
     * No. of times that templates were not found when decoding a data flowset.
     */
    NF9_STAT_MISSING_TEMPLATE_ERRORS,

    /**
     * Number of times that data and options templates expired.
     */
    NF9_STAT_EXPIRED_OBJECTS,

    /**
     * Current memory usage for storing template and options, in bytes.
     */
    NF9_STAT_MEMORY_USAGE,
};

/**
 * @brief Flags describing options of a NetFlow decoder.
 */
enum nf9_opt {

    /**
     * Memory limit in bytes for cached templates and options.
     *
     * @note This is an approximate value, real memory usage may be
     * larger than what is set by this option.
     */
    NF9_OPT_MAX_MEM_USAGE,

    /**
     * Duration (in seconds) that cached data templates are valid for.
     *
     * Decoding a data flowset that uses a template older than this
     * many seconds results in a decoding error.
     */
    NF9_OPT_TEMPLATE_EXPIRE_TIME,

    /**
     * Duration (in seconds) that options are valid for.
     *
     * This is like ::NF9_OPT_TEMPLATE_EXPIRE_TIME, but for option
     * values.
     */
    NF9_OPT_OPTION_EXPIRE_TIME,
};

/**
 * @brief Holds the address of a device that generated a NetFlow packet.
 */
typedef union nf9_addr {
    sa_family_t family;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
} nf9_addr;

#define NF9_FIELD_F0 (NF9_DATA_FIELD(0))
#define NF9_FIELD_IN_BYTES (NF9_DATA_FIELD(1))
#define NF9_FIELD_IN_PKTS (NF9_DATA_FIELD(2))
#define NF9_FIELD_FLOWS (NF9_DATA_FIELD(3))
#define NF9_FIELD_PROTOCOL (NF9_DATA_FIELD(4))
#define NF9_FIELD_TOS (NF9_DATA_FIELD(5))
#define NF9_FIELD_TCP_FLAGS (NF9_DATA_FIELD(6))
#define NF9_FIELD_L4_SRC_PORT (NF9_DATA_FIELD(7))
#define NF9_FIELD_IPV4_SRC_ADDR (NF9_DATA_FIELD(8))
#define NF9_FIELD_SRC_MASK (NF9_DATA_FIELD(9))
#define NF9_FIELD_INPUT_SNMP (NF9_DATA_FIELD(10))
#define NF9_FIELD_L4_DST_PORT (NF9_DATA_FIELD(11))
#define NF9_FIELD_IPV4_DST_ADDR (NF9_DATA_FIELD(12))
#define NF9_FIELD_DST_MASK (NF9_DATA_FIELD(13))
#define NF9_FIELD_OUTPUT_SNMP (NF9_DATA_FIELD(14))
#define NF9_FIELD_IPV4_NEXT_HOP (NF9_DATA_FIELD(15))
#define NF9_FIELD_SRC_AS (NF9_DATA_FIELD(16))
#define NF9_FIELD_DST_AS (NF9_DATA_FIELD(17))
#define NF9_FIELD_BGP_IPV4_NEXT_HOP (NF9_DATA_FIELD(18))
#define NF9_FIELD_MUL_DST_PKTS (NF9_DATA_FIELD(19))
#define NF9_FIELD_MUL_DST_BYTES (NF9_DATA_FIELD(20))
#define NF9_FIELD_LAST_SWITCHED (NF9_DATA_FIELD(21))
#define NF9_FIELD_FIRST_SWITCHED (NF9_DATA_FIELD(22))
#define NF9_FIELD_OUT_BYTES (NF9_DATA_FIELD(23))
#define NF9_FIELD_OUT_PKTS (NF9_DATA_FIELD(24))
#define NF9_FIELD_F25 (NF9_DATA_FIELD(25))
#define NF9_FIELD_F26 (NF9_DATA_FIELD(26))
#define NF9_FIELD_IPV6_SRC_ADDR (NF9_DATA_FIELD(27))
#define NF9_FIELD_IPV6_DST_ADDR (NF9_DATA_FIELD(28))
#define NF9_FIELD_IPV6_SRC_MASK (NF9_DATA_FIELD(29))
#define NF9_FIELD_IPV6_DST_MASK (NF9_DATA_FIELD(30))
#define NF9_FIELD_IPV6_FLOW_LABEL (NF9_DATA_FIELD(31))
#define NF9_FIELD_ICMP_TYPE (NF9_DATA_FIELD(32))
#define NF9_FIELD_MUL_IGMP_TYPE (NF9_DATA_FIELD(33))
#define NF9_FIELD_SAMPLING_INTERVAL (NF9_DATA_FIELD(34))
#define NF9_FIELD_SAMPLING_ALGORITHM (NF9_DATA_FIELD(35))
#define NF9_FIELD_FLOW_ACTIVE_TIMEOUT (NF9_DATA_FIELD(36))
#define NF9_FIELD_FLOW_INACTIVE_TIMEOUT (NF9_DATA_FIELD(37))
#define NF9_FIELD_ENGINE_TYPE (NF9_DATA_FIELD(38))
#define NF9_FIELD_ENGINE_ID (NF9_DATA_FIELD(39))
#define NF9_FIELD_TOTAL_BYTES_EXP (NF9_DATA_FIELD(40))
#define NF9_FIELD_TOTAL_PKTS_EXP (NF9_DATA_FIELD(41))
#define NF9_FIELD_TOTAL_FLOWS_EXP (NF9_DATA_FIELD(42))
#define NF9_FIELD_F43 (NF9_DATA_FIELD(43))
#define NF9_FIELD_F44 (NF9_DATA_FIELD(44))
#define NF9_FIELD_F45 (NF9_DATA_FIELD(45))
#define NF9_FIELD_MPLS_TOP_LABEL_TYPE (NF9_DATA_FIELD(46))
#define NF9_FIELD_MPLS_TOP_LABEL_IP_ADDR (NF9_DATA_FIELD(47))
#define NF9_FIELD_FLOW_SAMPLER_ID (NF9_DATA_FIELD(48))
#define NF9_FIELD_FLOW_SAMPLER_MODE (NF9_DATA_FIELD(49))
#define NF9_FIELD_FLOW_SAMPLER_RANDOM_INTERVAL (NF9_DATA_FIELD(50))
#define NF9_FIELD_F51 (NF9_DATA_FIELD(51))
#define NF9_FIELD_F52 (NF9_DATA_FIELD(52))
#define NF9_FIELD_F53 (NF9_DATA_FIELD(53))
#define NF9_FIELD_F54 (NF9_DATA_FIELD(54))
#define NF9_FIELD_DST_TOS (NF9_DATA_FIELD(55))
#define NF9_FIELD_SRC_MAC (NF9_DATA_FIELD(56))
#define NF9_FIELD_DST_MAC (NF9_DATA_FIELD(57))
#define NF9_FIELD_SRC_VLAN (NF9_DATA_FIELD(58))
#define NF9_FIELD_DST_VLAN (NF9_DATA_FIELD(59))
#define NF9_FIELD_IP_PROTOCOL_VERSION (NF9_DATA_FIELD(60))
#define NF9_FIELD_DIRECTION (NF9_DATA_FIELD(61))
#define NF9_FIELD_IPV6_NEXT_HOP (NF9_DATA_FIELD(62))
#define NF9_FIELD_BGP_IPV6_NEXT_HOP (NF9_DATA_FIELD(63))
#define NF9_FIELD_IPV6_OPTION_HEADERS (NF9_DATA_FIELD(64))
#define NF9_FIELD_F65 (NF9_DATA_FIELD(65))
#define NF9_FIELD_F66 (NF9_DATA_FIELD(66))
#define NF9_FIELD_F67 (NF9_DATA_FIELD(67))
#define NF9_FIELD_F68 (NF9_DATA_FIELD(68))
#define NF9_FIELD_F69 (NF9_DATA_FIELD(69))
#define NF9_FIELD_MPLS_LABEL_1 (NF9_DATA_FIELD(70))
#define NF9_FIELD_MPLS_LABEL_2 (NF9_DATA_FIELD(71))
#define NF9_FIELD_MPLS_LABEL_3 (NF9_DATA_FIELD(72))
#define NF9_FIELD_MPLS_LABEL_4 (NF9_DATA_FIELD(73))
#define NF9_FIELD_MPLS_LABEL_5 (NF9_DATA_FIELD(74))
#define NF9_FIELD_MPLS_LABEL_6 (NF9_DATA_FIELD(75))
#define NF9_FIELD_MPLS_LABEL_7 (NF9_DATA_FIELD(76))
#define NF9_FIELD_MPLS_LABEL_8 (NF9_DATA_FIELD(77))
#define NF9_FIELD_MPLS_LABEL_9 (NF9_DATA_FIELD(78))
#define NF9_FIELD_MPLS_LABEL_10 (NF9_DATA_FIELD(79))
#define NF9_FIELD_IN_DST_MAC (NF9_DATA_FIELD(80))
#define NF9_FIELD_OUT_SRC_MAC (NF9_DATA_FIELD(81))
#define NF9_FIELD_IF_NAME (NF9_DATA_FIELD(82))
#define NF9_FIELD_IF_DESC (NF9_DATA_FIELD(83))
#define NF9_FIELD_SAMPLER_NAME (NF9_DATA_FIELD(84))
#define NF9_FIELD_IN_PERMANENT_BYTES (NF9_DATA_FIELD(85))
#define NF9_FIELD_IN_PERMANENT_PKTS (NF9_DATA_FIELD(86))
#define NF9_FIELD_F87 (NF9_DATA_FIELD(87))
#define NF9_FIELD_FRAGMENT_OFFSET (NF9_DATA_FIELD(88))
#define NF9_FIELD_FORWARDING_STATUS (NF9_DATA_FIELD(89))
#define NF9_FIELD_MPLS_PAL_RD (NF9_DATA_FIELD(90))
#define NF9_FIELD_MPLS_PREFIX_LEN (NF9_DATA_FIELD(91))
#define NF9_FIELD_SRC_TRAFFIC_INDEX (NF9_DATA_FIELD(92))
#define NF9_FIELD_DST_TRAFFIC_INDEX (NF9_DATA_FIELD(93))
#define NF9_FIELD_APPLICATION_DESCRIPTION (NF9_DATA_FIELD(94))
#define NF9_FIELD_APPLICATION_TAG (NF9_DATA_FIELD(95))
#define NF9_FIELD_APPLICATION_NAME (NF9_DATA_FIELD(96))
#define NF9_FIELD_F97 (NF9_DATA_FIELD(97))
#define NF9_FIELD_postipDiffServCodePoint (NF9_DATA_FIELD(98))
#define NF9_FIELD_replication_factor (NF9_DATA_FIELD(99))
#define NF9_FIELD_DEPRECATED (NF9_DATA_FIELD(100))
#define NF9_FIELD_F101 (NF9_DATA_FIELD(101))
#define NF9_FIELD_layer2packetSectionOffset (NF9_DATA_FIELD(102))
#define NF9_FIELD_layer2packetSectionSize (NF9_DATA_FIELD(103))
#define NF9_FIELD_layer2packetSectionData (NF9_DATA_FIELD(104))
#define NF9_FIELD_F105 (NF9_DATA_FIELD(105))
#define NF9_FIELD_F106 (NF9_DATA_FIELD(106))
#define NF9_FIELD_F107 (NF9_DATA_FIELD(107))
#define NF9_FIELD_F108 (NF9_DATA_FIELD(108))
#define NF9_FIELD_F109 (NF9_DATA_FIELD(109))
#define NF9_FIELD_F110 (NF9_DATA_FIELD(110))
#define NF9_FIELD_F111 (NF9_DATA_FIELD(111))
#define NF9_FIELD_F112 (NF9_DATA_FIELD(112))
#define NF9_FIELD_F113 (NF9_DATA_FIELD(113))
#define NF9_FIELD_F114 (NF9_DATA_FIELD(114))
#define NF9_FIELD_F115 (NF9_DATA_FIELD(115))
#define NF9_FIELD_F116 (NF9_DATA_FIELD(116))
#define NF9_FIELD_F117 (NF9_DATA_FIELD(117))
#define NF9_FIELD_F118 (NF9_DATA_FIELD(118))
#define NF9_FIELD_F119 (NF9_DATA_FIELD(119))
#define NF9_FIELD_F120 (NF9_DATA_FIELD(120))
#define NF9_FIELD_F121 (NF9_DATA_FIELD(121))
#define NF9_FIELD_F122 (NF9_DATA_FIELD(122))
#define NF9_FIELD_F123 (NF9_DATA_FIELD(123))
#define NF9_FIELD_F124 (NF9_DATA_FIELD(124))
#define NF9_FIELD_F125 (NF9_DATA_FIELD(125))
#define NF9_FIELD_F126 (NF9_DATA_FIELD(126))
#define NF9_FIELD_F127 (NF9_DATA_FIELD(127))
#define NF9_FIELD_F128 (NF9_DATA_FIELD(128))
#define NF9_FIELD_F129 (NF9_DATA_FIELD(129))
#define NF9_FIELD_F130 (NF9_DATA_FIELD(130))
#define NF9_FIELD_F131 (NF9_DATA_FIELD(131))
#define NF9_FIELD_F132 (NF9_DATA_FIELD(132))
#define NF9_FIELD_F133 (NF9_DATA_FIELD(133))
#define NF9_FIELD_F134 (NF9_DATA_FIELD(134))
#define NF9_FIELD_F135 (NF9_DATA_FIELD(135))
#define NF9_FIELD_F136 (NF9_DATA_FIELD(136))
#define NF9_FIELD_F137 (NF9_DATA_FIELD(137))
#define NF9_FIELD_F138 (NF9_DATA_FIELD(138))
#define NF9_FIELD_F139 (NF9_DATA_FIELD(139))
#define NF9_FIELD_F140 (NF9_DATA_FIELD(140))
#define NF9_FIELD_F141 (NF9_DATA_FIELD(141))
#define NF9_FIELD_F142 (NF9_DATA_FIELD(142))
#define NF9_FIELD_F143 (NF9_DATA_FIELD(143))
#define NF9_FIELD_F144 (NF9_DATA_FIELD(144))
#define NF9_FIELD_F145 (NF9_DATA_FIELD(145))
#define NF9_FIELD_F146 (NF9_DATA_FIELD(146))
#define NF9_FIELD_F147 (NF9_DATA_FIELD(147))
#define NF9_FIELD_F148 (NF9_DATA_FIELD(148))
#define NF9_FIELD_F149 (NF9_DATA_FIELD(149))
#define NF9_FIELD_F150 (NF9_DATA_FIELD(150))
#define NF9_FIELD_F151 (NF9_DATA_FIELD(151))
#define NF9_FIELD_F152 (NF9_DATA_FIELD(152))
#define NF9_FIELD_F153 (NF9_DATA_FIELD(153))
#define NF9_FIELD_F154 (NF9_DATA_FIELD(154))
#define NF9_FIELD_F155 (NF9_DATA_FIELD(155))
#define NF9_FIELD_F156 (NF9_DATA_FIELD(156))
#define NF9_FIELD_F157 (NF9_DATA_FIELD(157))
#define NF9_FIELD_F158 (NF9_DATA_FIELD(158))
#define NF9_FIELD_F159 (NF9_DATA_FIELD(159))
#define NF9_FIELD_F160 (NF9_DATA_FIELD(160))
#define NF9_FIELD_F161 (NF9_DATA_FIELD(161))
#define NF9_FIELD_F162 (NF9_DATA_FIELD(162))
#define NF9_FIELD_F163 (NF9_DATA_FIELD(163))
#define NF9_FIELD_F164 (NF9_DATA_FIELD(164))
#define NF9_FIELD_F165 (NF9_DATA_FIELD(165))
#define NF9_FIELD_F166 (NF9_DATA_FIELD(166))
#define NF9_FIELD_F167 (NF9_DATA_FIELD(167))
#define NF9_FIELD_F168 (NF9_DATA_FIELD(168))
#define NF9_FIELD_F169 (NF9_DATA_FIELD(169))
#define NF9_FIELD_F170 (NF9_DATA_FIELD(170))
#define NF9_FIELD_F171 (NF9_DATA_FIELD(171))
#define NF9_FIELD_F172 (NF9_DATA_FIELD(172))
#define NF9_FIELD_F173 (NF9_DATA_FIELD(173))
#define NF9_FIELD_F174 (NF9_DATA_FIELD(174))
#define NF9_FIELD_F175 (NF9_DATA_FIELD(175))
#define NF9_FIELD_F176 (NF9_DATA_FIELD(176))
#define NF9_FIELD_F177 (NF9_DATA_FIELD(177))
#define NF9_FIELD_F178 (NF9_DATA_FIELD(178))
#define NF9_FIELD_F179 (NF9_DATA_FIELD(179))
#define NF9_FIELD_F180 (NF9_DATA_FIELD(180))
#define NF9_FIELD_F181 (NF9_DATA_FIELD(181))
#define NF9_FIELD_F182 (NF9_DATA_FIELD(182))
#define NF9_FIELD_F183 (NF9_DATA_FIELD(183))
#define NF9_FIELD_F184 (NF9_DATA_FIELD(184))
#define NF9_FIELD_F185 (NF9_DATA_FIELD(185))
#define NF9_FIELD_F186 (NF9_DATA_FIELD(186))
#define NF9_FIELD_F187 (NF9_DATA_FIELD(187))
#define NF9_FIELD_F188 (NF9_DATA_FIELD(188))
#define NF9_FIELD_F189 (NF9_DATA_FIELD(189))
#define NF9_FIELD_F190 (NF9_DATA_FIELD(190))
#define NF9_FIELD_F191 (NF9_DATA_FIELD(191))
#define NF9_FIELD_F192 (NF9_DATA_FIELD(192))
#define NF9_FIELD_F193 (NF9_DATA_FIELD(193))
#define NF9_FIELD_F194 (NF9_DATA_FIELD(194))
#define NF9_FIELD_F195 (NF9_DATA_FIELD(195))
#define NF9_FIELD_F196 (NF9_DATA_FIELD(196))
#define NF9_FIELD_F197 (NF9_DATA_FIELD(197))
#define NF9_FIELD_F198 (NF9_DATA_FIELD(198))
#define NF9_FIELD_F199 (NF9_DATA_FIELD(199))
#define NF9_FIELD_F200 (NF9_DATA_FIELD(200))
#define NF9_FIELD_F201 (NF9_DATA_FIELD(201))
#define NF9_FIELD_F202 (NF9_DATA_FIELD(202))
#define NF9_FIELD_F203 (NF9_DATA_FIELD(203))
#define NF9_FIELD_F204 (NF9_DATA_FIELD(204))
#define NF9_FIELD_F205 (NF9_DATA_FIELD(205))
#define NF9_FIELD_F206 (NF9_DATA_FIELD(206))
#define NF9_FIELD_F207 (NF9_DATA_FIELD(207))
#define NF9_FIELD_F208 (NF9_DATA_FIELD(208))
#define NF9_FIELD_F209 (NF9_DATA_FIELD(209))
#define NF9_FIELD_F210 (NF9_DATA_FIELD(210))
#define NF9_FIELD_F211 (NF9_DATA_FIELD(211))
#define NF9_FIELD_F212 (NF9_DATA_FIELD(212))
#define NF9_FIELD_F213 (NF9_DATA_FIELD(213))
#define NF9_FIELD_F214 (NF9_DATA_FIELD(214))
#define NF9_FIELD_F215 (NF9_DATA_FIELD(215))
#define NF9_FIELD_F216 (NF9_DATA_FIELD(216))
#define NF9_FIELD_F217 (NF9_DATA_FIELD(217))
#define NF9_FIELD_F218 (NF9_DATA_FIELD(218))
#define NF9_FIELD_F219 (NF9_DATA_FIELD(219))
#define NF9_FIELD_F220 (NF9_DATA_FIELD(220))
#define NF9_FIELD_F221 (NF9_DATA_FIELD(221))
#define NF9_FIELD_F222 (NF9_DATA_FIELD(222))
#define NF9_FIELD_F223 (NF9_DATA_FIELD(223))
#define NF9_FIELD_F224 (NF9_DATA_FIELD(224))
#define NF9_FIELD_F225 (NF9_DATA_FIELD(225))
#define NF9_FIELD_F226 (NF9_DATA_FIELD(226))
#define NF9_FIELD_F227 (NF9_DATA_FIELD(227))
#define NF9_FIELD_F228 (NF9_DATA_FIELD(228))
#define NF9_FIELD_F229 (NF9_DATA_FIELD(229))
#define NF9_FIELD_F230 (NF9_DATA_FIELD(230))
#define NF9_FIELD_F231 (NF9_DATA_FIELD(231))
#define NF9_FIELD_F232 (NF9_DATA_FIELD(232))
#define NF9_FIELD_F233 (NF9_DATA_FIELD(233))
#define NF9_FIELD_Ingress_VRFID (NF9_DATA_FIELD(234))
#define NF9_FIELD_Egress_VRFID (NF9_DATA_FIELD(235))

#define NF9_SCOPE_FIELD_NONE (NF9_SCOPE_FIELD(0))
#define NF9_SCOPE_FIELD_SYSTEM (NF9_SCOPE_FIELD(1))
#define NF9_SCOPE_FIELD_INTERFACE (NF9_SCOPE_FIELD(2))
#define NF9_SCOPE_FIELD_LINE_CARD (NF9_SCOPE_FIELD(3))
#define NF9_SCOPE_FIELD_NETFLOW_CACHE (NF9_SCOPE_FIELD(4))
#define NF9_SCOPE_FIELD_TEMPLATE (NF9_SCOPE_FIELD(5))

typedef struct nf9_state nf9_state;
typedef struct nf9_packet nf9_packet;
typedef struct nf9_stats nf9_stats;

/**
 * @brief Structure that defines NetFlow field.
 */
typedef struct nf9_fieldval
{
    nf9_field field;      /**< field number */
    size_t size;          /**< field size in bytes */
    const uint8_t* value; /**< field value */
} nf9_fieldval;

/**
 * @brief Get an error message for an error code.
 *
 * The returned string mustn't be freed.
 *
 * @param err Error code.
 * @return Error message.
 */
NF9_API const char* nf9_strerror(int err);

/**
 * @brief Create a NetFlow9 decoder.
 *
 * The returned object holds NetFlow templates and option values which
 * are used to later decode data records.
 *
 * The returned object must be later freed with nf9_free().
 *
 * @param flags Bitmask of flags from enum ::nf9_state_flag.
 * @return An instance of the decoder.
 */
NF9_API nf9_state* nf9_init(int flags);

/**
 * @brief Free a NetFlow9 decoder.
 *
 * @param state A state object created by nf9_init().
 */
NF9_API void nf9_free(nf9_state* state);

/**
 * @brief Decode a NetFlow9 packet.
 *
 * @p buf must point to a buffer which contains NetFlow data
 * (e.g. received from a UDP socket), and @p addr must hold the
 * address of the packet sender.
 *
 * On success, the pointer to a packet is written to `*result`.
 * It must later be freed with nf9_free_packet().  On failure,
 * nothing is written to `*result`.
 *
 * @param state A state object created by nf9_init()
 * @param[out] result Pointer to a result.  `*result` need not point to anything
 * meaningful, the function will override it.
 * @param buf Packet bytes.
 * @param len Size of @p buf.
 * @param addr Address of packet sender.
 * @return 0 on success; on error, a value from enum ::nf9_error.
 */
NF9_API int nf9_decode(nf9_state* state, nf9_packet** result,
                       const uint8_t* buf, size_t len, const nf9_addr* addr);

/**
 * @brief Free a packet.
 *
 * @param pkt Packet created in nf9_decode().
 */
NF9_API void nf9_free_packet(const nf9_packet* pkt);

/**
 * @brief Get the number of flowsets in a NetFlow packet.
 *
 * @param pkt Decoded NetFlow packet, created by nf9_decode().
 * @return Number of flowsets in @p pkt.
 */
NF9_API size_t nf9_get_num_flowsets(const nf9_packet* pkt);

/**
 * @brief Get the UNIX timestamp from a NetFlow packet.
 *
 * @param pkt Decoded NetFlow packet, created by nf9_decode().
 * @return UNIX timestamp in the NetFlow header.
 */
NF9_API uint32_t nf9_get_timestamp(const nf9_packet* pkt);

/**
 * @brief Get the source ID from a NetFlow packet.
 *
 * @param pkt Decoded NetFlow packet, created by nf9_decode().
 * @return Source ID in the NetFlow header.
 */
NF9_API uint32_t nf9_get_source_id(const nf9_packet* pkt);

/**
 * @brief Get the system uptime in milliseconds from a NetFlow packet.
 *
 * @param pkt Decoded NetFlow packet, created by nf9_decode().
 * @return Uptime in milliseconds of the device that generated the packet.
 */
NF9_API uint32_t nf9_get_uptime(const nf9_packet* pkt);

/**
 * @brief Get the type of flowset in a NetFlow packet.
 *
 * @pre @p flowset must be < `nf9_get_num_flowsets(pkt)`.
 *
 * @param pkt Decoded NetFlow packet, created with nf9_decode().
 * @param flowset Index of the flowset.
 * @return The flowset type - one of the values of enum ::nf9_flowset_type.
 */
NF9_API int nf9_get_flowset_type(const nf9_packet* pkt, unsigned flowset);

/**
 * @brief Get the number of flows in a specific flowset in a NetFlow packet.
 *
 * @pre @p flowset must be < `nf9_get_num_flowsets(pkt)`.
 *
 * @param pkt Decoded NetFlow packet, created with nf9_decode().
 * @param flowset The flowset index.
 * @return Number of flows in the flowset.
 */
NF9_API size_t nf9_get_num_flows(const nf9_packet* pkt, unsigned flowset);

/**
 * @brief Get the value of a field from a NetFlow data record.
 *
 * @pre @p flowset must be < `nf9_get_num_flowsets(pkt)`.
 * @pre @p flow must be < `nf9_get_num_flows(pkt, flowset)`.
 *
 * @param pkt Decoded NetFlow packet, created with nf9_decode().
 * @param flowset Index of the flowset.
 * @param flownum Index of the flow within the flowset.
 * @param field The field ID - one of `NF9_FIELD_*`.
 * @param[out] dst Pointer to a location where value of the field will be
 * written.
 * @param[in,out] length Initially points to size of @p dst.  On success,
 * overwritten with number of bytes written to @p dst.
 * @return 0 on success; on error, a value from enum ::nf9_error.
 */
NF9_API int nf9_get_field(const nf9_packet* pkt, unsigned flowset,
                          unsigned flownum, nf9_field field, void* dst,
                          size_t* length);

/**
 * @brief Get values of all fields from a NetFlow data record.
 * Obtained fields are valid as long as nf9_packet exists - they do not need
 * to be freed.
 *
 * @pre @p flowset must be < `nf9_get_num_flowsets(pkt)`.
 * @pre @p flow must be < `nf9_get_num_flows(pkt, flowset)`.
 *
 * @param pkt Decoded NetFlow packet, created with nf9_decode().
 * @param flowset Index of the flowset.
 * @param flownum Index of the flow within the flowset.
 * @param[out] out Pointer to a location where value of the fields will be
 * written.
 * @param[in,out] size Initially points to size of @p out.  On success,
 * overwritten with number of fields written to @p out.
 * @return 0 on success; on error, a value from enum ::nf9_error.
 */
NF9_API int nf9_get_all_fields(const nf9_packet* pkt, unsigned flowset,
                               unsigned flownum, nf9_fieldval* out,
                               size_t* size);

/**
 * @brief Get the value of an option from a NetFlow packet.
 *
 * @param pkt Decoded NetFlow packet.
 * @param field The option to get, one of `NF9_FIELD_*`.
 * @param[out] dst Pointer to location where value of the option will be
 * written.
 * @param[in,out] length Initially points to size of @p dst.  On success,
 * overwritten with number of bytes written to @p dst.
 * @return 0 on success; on error, a value from enum ::nf9_error.
 */
NF9_API int nf9_get_option(const nf9_packet* pkt, nf9_field field, void* dst,
                           size_t* length);

/**
 * @brief Get the sampling rate used for a flow within a NetFlow packet.
 *
 * @pre @p flowset must be < `nf9_get_num_flowsets(pkt)`.
 * @pre @p flow must be < `nf9_get_num_flows(pkt, flowset)`.
 * @pre Flag NF9_STORE_SAMPLING_RATES need to be set in nf9_init().
 *
 * @param pkt Decoded NetFlow packet, created with nf9_decode().
 * @param flowset Index of the flowset.
 * @param flownum Index of the flow within the flowset.
 * @param[out] sampling The sampling rate.
 * @param[out] sampling_info Detailed information about sampling obtaining
 * methods and errors. A value from enum ::nf9_sampling_info.
 * @return 0 on success; on error, a value from enum ::nf9_error.
 */
NF9_API int nf9_get_sampling_rate(const nf9_packet* pkt, unsigned flowset,
                                  unsigned flownum, uint32_t* sampling,
                                  int* sampling_info);

/**
 * @brief Get statistics of a NetFlow decoder.
 *
 * The returned object must be freed with nf9_free_stats() when it's
 * no longer used.
 *
 * @return An object which holds decoder statistics.
 */
NF9_API const nf9_stats* nf9_get_stats(const nf9_state* state);

/**
 * @brief Get a specific statistic.
 *
 * @param stats Object returned by nf9_get_stats().
 * @param stat The statistic to get, one of the values of enum ::nf9_stat.
 * @return Value of the statistic.
 */
NF9_API uint64_t nf9_get_stat(const nf9_stats* stats, int stat);

/**
 * @brief Free NetFlow decoder statistics.
 *
 * @param stats Object returned from nf9_get_stats().
 */
NF9_API void nf9_free_stats(const nf9_stats* stats);

/**
 * @brief Set NetFlow9 decoder options.
 *
 * @param state Decoder object created by nf9_init().
 * @param opt The option to set (one of the values of enum ::nf9_opt).
 * @param value The new value for the option.
 * @return 0 on success; on error, a value from enum ::nf9_error.
 */
NF9_API int nf9_ctl(nf9_state* state, int opt, long value);

#ifdef __cplusplus
}
#endif

#endif  // NETFLOW9_H
