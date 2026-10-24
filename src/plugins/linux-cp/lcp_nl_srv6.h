/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 as38656
 */

#ifndef __LCP_NL_SRV6_H__
#define __LCP_NL_SRV6_H__

#include <linux/netlink.h>

#include <vnet/ip/ip.h>
#include <vnet/fib/fib_types.h>

/*
 * Kernel SRv6 routes carry a seg6 (encapsulation) or a seg6local (local SID)
 * lightweight tunnel. libnl cannot parse either kind, so linux-nl reads
 * these route messages itself into the types below.
 */

typedef enum lcp_nl_srv6_encap_mode_t_
{
  LCP_NL_SRV6_ENCAP_MODE_ENCAP,	    /* H.Encaps */
  LCP_NL_SRV6_ENCAP_MODE_ENCAP_RED, /* H.Encaps.Red */
} lcp_nl_srv6_encap_mode_t;

/** One next hop of an SRv6 encapsulation route */
typedef struct lcp_nl_srv6_encap_t_
{
  lcp_nl_srv6_encap_mode_t mode;
  /** Segment list (vector), in the order the packet visits the segments */
  ip6_address_t *segments;
  u32 weight;
} lcp_nl_srv6_encap_t;

typedef enum lcp_nl_srv6_action_t_
{
  LCP_NL_SRV6_ACTION_END,
  LCP_NL_SRV6_ACTION_END_X,
  LCP_NL_SRV6_ACTION_END_T,
  LCP_NL_SRV6_ACTION_END_DX4,
  LCP_NL_SRV6_ACTION_END_DX6,
  LCP_NL_SRV6_ACTION_END_DT4,
  LCP_NL_SRV6_ACTION_END_DT6,
  LCP_NL_SRV6_ACTION_END_DT46,
} lcp_nl_srv6_action_t;

/** A local SID */
typedef struct lcp_nl_srv6_local_t_
{
  lcp_nl_srv6_action_t action;
  /** NEXT-C-SID flavor (RFC 9800): block and node/function bits of a C-SID */
  u8 next_csid;
  u8 lcblock_bits;
  u8 lcnode_fn_bits;
  /** End.T, End.DT4, End.DT6, End.DT46: kernel id of the lookup table */
  u32 table_id;
  /** End.X, End.DX4, End.DX6: next hop and its host interface index */
  ip46_address_t nh;
  u32 oif;
} lcp_nl_srv6_local_t;

typedef enum lcp_nl_srv6_route_kind_t_
{
  LCP_NL_SRV6_ROUTE_ENCAP,
  LCP_NL_SRV6_ROUTE_LOCAL,
} lcp_nl_srv6_route_kind_t;

typedef struct lcp_nl_srv6_route_t_
{
  lcp_nl_srv6_route_kind_t kind;
  fib_prefix_t prefix;
  /** Kernel table id, e.g. 254 for the main table */
  u32 table_id;
  u8 protocol;
  u32 priority;
  /** LCP_NL_SRV6_ROUTE_ENCAP: one entry per next hop (vector) */
  lcp_nl_srv6_encap_t *encaps;
  /** LCP_NL_SRV6_ROUTE_LOCAL */
  lcp_nl_srv6_local_t local;
} lcp_nl_srv6_route_t;

typedef enum lcp_nl_srv6_parse_rc_t_
{
  /** Not an SRv6 route. libnl parses it as before. */
  LCP_NL_SRV6_PARSE_NOT_SRV6,
  LCP_NL_SRV6_PARSE_OK,
  /** An SRv6 route that VPP cannot program. */
  LCP_NL_SRV6_PARSE_UNSUPPORTED,
  LCP_NL_SRV6_PARSE_MALFORMED,
} lcp_nl_srv6_parse_rc_t;

/**
 * Parse an RTM_NEWROUTE or RTM_DELROUTE message.
 *
 * On LCP_NL_SRV6_PARSE_OK the route must be released with
 * lcp_nl_srv6_route_free. On LCP_NL_SRV6_PARSE_UNSUPPORTED and
 * LCP_NL_SRV6_PARSE_MALFORMED, *reason is a vector that says why.
 */
extern lcp_nl_srv6_parse_rc_t lcp_nl_srv6_route_parse (const struct nlmsghdr *nlh,
						       lcp_nl_srv6_route_t *route, u8 **reason);
extern void lcp_nl_srv6_route_free (lcp_nl_srv6_route_t *route);

extern format_function_t format_lcp_nl_srv6_route;
extern format_function_t format_lcp_nl_srv6_segments;

#endif /* __LCP_NL_SRV6_H__ */
