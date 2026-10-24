/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 as38656
 */

#ifndef __LCP_ROUTER_H__
#define __LCP_ROUTER_H__

#include <vnet/fib/fib_table.h>

/* A FIB table that the router uses for kernel routes */
typedef struct lcp_router_table_t_
{
  uint32_t nlt_id;
  fib_protocol_t nlt_proto;
  u32 nlt_fib_index;
  u32 nlt_mfib_index;
  u32 nlt_refs;
} lcp_router_table_t;

/** VPP interface of a host interface index, ~0 if it has none */
extern u32 lcp_router_intf_h2p (u32 host);

/** VPP table id of a kernel table id */
extern u32 lcp_router_table_k2f (u32 k);

/** Find a table by VPP table id */
extern lcp_router_table_t *lcp_router_table_find (u32 id, fib_protocol_t fproto);

/** Create or lock a table by kernel table id */
extern lcp_router_table_t *lcp_router_table_add_or_lock (u32 id, fib_protocol_t fproto);
extern void lcp_router_table_unlock (lcp_router_table_t *nlt);

/** FIB source for routes of a kernel routing protocol (RTPROT_*) */
extern fib_source_t lcp_router_proto_fib_source (u8 rt_proto);

/** FIB entry flags for a kernel route type (RTN_*), table id and protocol */
extern fib_entry_flag_t lcp_router_route_mk_entry_flags (u8 rtype, int table_id, u8 rproto);

/**
 * A kernel route without SRv6 has replaced the route of the prefix in the
 * table (kernel table id). Forgets the SRv6 paths that the prefix had.
 */
extern void lcp_router_srv6_route_replaced (u32 table_id, const fib_prefix_t *pfx);

#endif /* __LCP_ROUTER_H__ */
