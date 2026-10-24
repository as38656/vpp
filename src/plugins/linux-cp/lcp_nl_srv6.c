/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 as38656
 */

#include <linux/rtnetlink.h>
#include <linux/lwtunnel.h>
#include <linux/seg6.h>
#include <linux/seg6_iptunnel.h>
#include <linux/seg6_local.h>

#include <netlink/msg.h>
#include <netlink/attr.h>

#include <linux-cp/lcp_nl_srv6.h>

/* The kernel uses these lengths when a NEXT-C-SID flavor leaves them out */
#define LCP_NL_SRV6_LCBLOCK_BITS_DEF   32
#define LCP_NL_SRV6_LCNODE_FN_BITS_DEF 16

typedef struct lcp_nl_srv6_nh_t_
{
  struct nlattr *encap_type;
  struct nlattr *encap;
  u32 ifindex;
  u32 weight;
} lcp_nl_srv6_nh_t;

static lcp_nl_srv6_parse_rc_t
lcp_nl_srv6_fail (u8 **reason, lcp_nl_srv6_parse_rc_t rc, char *fmt, ...)
{
  va_list va;

  va_start (va, fmt);
  *reason = va_format (*reason, fmt, &va);
  va_end (va);

  return rc;
}

static u16
lcp_nl_srv6_nh_encap_type (const lcp_nl_srv6_nh_t *nh)
{
  return nh->encap_type ? nla_get_u16 (nh->encap_type) : LWTUNNEL_ENCAP_NONE;
}

static lcp_nl_srv6_parse_rc_t
lcp_nl_srv6_parse_nhs (struct nlattr **tb, lcp_nl_srv6_nh_t **nhs, u8 **reason)
{
  struct rtnexthop *rtnh;
  int len;

  if (!tb[RTA_MULTIPATH])
    {
      lcp_nl_srv6_nh_t nh = {
	.encap_type = tb[RTA_ENCAP_TYPE],
	.encap = tb[RTA_ENCAP],
	.ifindex = tb[RTA_OIF] ? nla_get_u32 (tb[RTA_OIF]) : 0,
	.weight = 1,
      };

      vec_add1 (*nhs, nh);
      return LCP_NL_SRV6_PARSE_OK;
    }

  rtnh = nla_data (tb[RTA_MULTIPATH]);
  len = nla_len (tb[RTA_MULTIPATH]);

  while (RTNH_OK (rtnh, len))
    {
      struct nlattr *ntb[RTA_MAX + 1];
      lcp_nl_srv6_nh_t nh;

      if (nla_parse (ntb, RTA_MAX, (struct nlattr *) RTNH_DATA (rtnh),
		     rtnh->rtnh_len - RTNH_LENGTH (0), NULL) < 0)
	return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_MALFORMED,
				 "next hop attributes do not parse");

      nh.encap_type = ntb[RTA_ENCAP_TYPE];
      nh.encap = ntb[RTA_ENCAP];
      nh.ifindex = rtnh->rtnh_ifindex;
      nh.weight = rtnh->rtnh_hops + 1;
      vec_add1 (*nhs, nh);

      len -= RTNH_ALIGN (rtnh->rtnh_len);
      rtnh = RTNH_NEXT (rtnh);
    }

  if (len != 0)
    return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_MALFORMED,
			     "multipath attribute has %d trailing bytes", len);

  return LCP_NL_SRV6_PARSE_OK;
}

static lcp_nl_srv6_parse_rc_t
lcp_nl_srv6_parse_prefix (const struct rtmsg *rtm, struct nlattr **tb, fib_prefix_t *pfx,
			  u8 **reason)
{
  u32 addr_len;

  switch (rtm->rtm_family)
    {
    case AF_INET:
      pfx->fp_proto = FIB_PROTOCOL_IP4;
      addr_len = sizeof (ip4_address_t);
      break;
    case AF_INET6:
      pfx->fp_proto = FIB_PROTOCOL_IP6;
      addr_len = sizeof (ip6_address_t);
      break;
    default:
      return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_UNSUPPORTED, "address family %u",
			       rtm->rtm_family);
    }

  if (rtm->rtm_dst_len > addr_len * 8)
    return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_MALFORMED, "prefix length %u",
			     rtm->rtm_dst_len);
  pfx->fp_len = rtm->rtm_dst_len;

  if (tb[RTA_DST])
    {
      if (nla_len (tb[RTA_DST]) != addr_len)
	return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_MALFORMED, "destination of %d bytes",
				 nla_len (tb[RTA_DST]));

      if (pfx->fp_proto == FIB_PROTOCOL_IP4)
	clib_memcpy (&pfx->fp_addr.ip4, nla_data (tb[RTA_DST]), addr_len);
      else
	clib_memcpy (&pfx->fp_addr.ip6, nla_data (tb[RTA_DST]), addr_len);
    }

  return LCP_NL_SRV6_PARSE_OK;
}

static lcp_nl_srv6_parse_rc_t
lcp_nl_srv6_parse_encap (struct nlattr *encap, lcp_nl_srv6_encap_t *e, u8 **reason)
{
  struct nlattr *tb[SEG6_IPTUNNEL_MAX + 1];
  struct seg6_iptunnel_encap *tun;
  struct ipv6_sr_hdr *srh;
  u32 len, srh_len, n_segments, i;

  if (!encap || nla_parse_nested (tb, SEG6_IPTUNNEL_MAX, encap, NULL) < 0 || !tb[SEG6_IPTUNNEL_SRH])
    return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_MALFORMED, "seg6 tunnel without SRH");

  len = nla_len (tb[SEG6_IPTUNNEL_SRH]);
  if (len < sizeof (*tun) + sizeof (*srh))
    return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_MALFORMED, "seg6 tunnel of %u bytes", len);

  tun = nla_data (tb[SEG6_IPTUNNEL_SRH]);
  srh = tun->srh;
  srh_len = (srh->hdrlen + 1) << 3;
  n_segments = srh->first_segment + 1;

  if (sizeof (*tun) + srh_len > len ||
      sizeof (*srh) + n_segments * sizeof (ip6_address_t) > srh_len)
    return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_MALFORMED,
			     "SRH of %u bytes with %u segments", srh_len, n_segments);

  switch (tun->mode)
    {
    case SEG6_IPTUN_MODE_ENCAP:
      e->mode = LCP_NL_SRV6_ENCAP_MODE_ENCAP;
      break;
    case SEG6_IPTUN_MODE_ENCAP_RED:
      e->mode = LCP_NL_SRV6_ENCAP_MODE_ENCAP_RED;
      break;
    default:
      return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_UNSUPPORTED, "seg6 mode %d", tun->mode);
    }

  if (sizeof (*srh) + n_segments * sizeof (ip6_address_t) < srh_len ||
      (srh->flags & SR6_FLAG1_HMAC))
    return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_UNSUPPORTED, "SRH with TLVs");

  /* segments[0] is the last segment of the path */
  for (i = 0; i < n_segments; i++)
    {
      ip6_address_t segment;

      clib_memcpy (&segment, &srh->segments[srh->first_segment - i], sizeof (segment));
      vec_add1 (e->segments, segment);
    }

  return LCP_NL_SRV6_PARSE_OK;
}

static lcp_nl_srv6_parse_rc_t
lcp_nl_srv6_parse_flavors (struct nlattr *flavors, u32 action, lcp_nl_srv6_local_t *l, u8 **reason)
{
  struct nlattr *tb[SEG6_LOCAL_FLV_MAX + 1];
  u32 ops;

  if (!flavors)
    return LCP_NL_SRV6_PARSE_OK;

  if (nla_parse_nested (tb, SEG6_LOCAL_FLV_MAX, flavors, NULL) < 0)
    return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_MALFORMED, "flavors do not parse");

  ops = tb[SEG6_LOCAL_FLV_OPERATION] ? nla_get_u32 (tb[SEG6_LOCAL_FLV_OPERATION]) : 0;
  if (ops == 0)
    return LCP_NL_SRV6_PARSE_OK;

  if (ops != (1 << SEG6_LOCAL_FLV_OP_NEXT_CSID) ||
      (action != SEG6_LOCAL_ACTION_END && action != SEG6_LOCAL_ACTION_END_X))
    return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_UNSUPPORTED, "flavors 0x%x on action %u",
			     ops, action);

  l->next_csid = 1;
  l->lcblock_bits = tb[SEG6_LOCAL_FLV_LCBLOCK_BITS] ? nla_get_u8 (tb[SEG6_LOCAL_FLV_LCBLOCK_BITS]) :
						      LCP_NL_SRV6_LCBLOCK_BITS_DEF;
  l->lcnode_fn_bits = tb[SEG6_LOCAL_FLV_LCNODE_FN_BITS] ?
			nla_get_u8 (tb[SEG6_LOCAL_FLV_LCNODE_FN_BITS]) :
			LCP_NL_SRV6_LCNODE_FN_BITS_DEF;

  return LCP_NL_SRV6_PARSE_OK;
}

/*
 * Without an oif the next hop is on the device of the route, which is how
 * routing daemons give link-local next hops. VPP cross-connects only to an
 * interface, so one of the two is needed.
 */
static lcp_nl_srv6_parse_rc_t
lcp_nl_srv6_parse_xconnect (struct nlattr **tb, int nh_attr, u32 nh_len, u32 route_oif,
			    lcp_nl_srv6_local_t *l, u8 **reason)
{
  if (!tb[nh_attr] || nla_len (tb[nh_attr]) != nh_len)
    return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_MALFORMED,
			     "cross-connect without a next hop");
  l->oif = tb[SEG6_LOCAL_OIF] ? nla_get_u32 (tb[SEG6_LOCAL_OIF]) : route_oif;
  if (!l->oif)
    return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_UNSUPPORTED,
			     "cross-connect without an output interface");

  if (nh_len == sizeof (ip4_address_t))
    clib_memcpy (&l->nh.ip4, nla_data (tb[nh_attr]), nh_len);
  else
    clib_memcpy (&l->nh.ip6, nla_data (tb[nh_attr]), nh_len);

  return LCP_NL_SRV6_PARSE_OK;
}

static lcp_nl_srv6_parse_rc_t
lcp_nl_srv6_parse_table (struct nlattr *table, lcp_nl_srv6_local_t *l, u8 **reason)
{
  if (!table)
    return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_MALFORMED, "lookup without a table");

  l->table_id = nla_get_u32 (table);

  return LCP_NL_SRV6_PARSE_OK;
}

static lcp_nl_srv6_parse_rc_t
lcp_nl_srv6_parse_local (struct nlattr *encap, u32 route_oif, lcp_nl_srv6_local_t *l, u8 **reason)
{
  struct nlattr *tb[SEG6_LOCAL_MAX + 1];
  lcp_nl_srv6_parse_rc_t rc;
  u32 action;

  if (!encap || nla_parse_nested (tb, SEG6_LOCAL_MAX, encap, NULL) < 0 || !tb[SEG6_LOCAL_ACTION])
    return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_MALFORMED,
			     "seg6local tunnel without action");

  action = nla_get_u32 (tb[SEG6_LOCAL_ACTION]);

  rc = lcp_nl_srv6_parse_flavors (tb[SEG6_LOCAL_FLAVORS], action, l, reason);
  if (rc != LCP_NL_SRV6_PARSE_OK)
    return rc;

  switch (action)
    {
    case SEG6_LOCAL_ACTION_END:
      l->action = LCP_NL_SRV6_ACTION_END;
      return LCP_NL_SRV6_PARSE_OK;
    case SEG6_LOCAL_ACTION_END_X:
      l->action = LCP_NL_SRV6_ACTION_END_X;
      return lcp_nl_srv6_parse_xconnect (tb, SEG6_LOCAL_NH6, sizeof (ip6_address_t), route_oif, l,
					 reason);
    case SEG6_LOCAL_ACTION_END_DX6:
      l->action = LCP_NL_SRV6_ACTION_END_DX6;
      return lcp_nl_srv6_parse_xconnect (tb, SEG6_LOCAL_NH6, sizeof (ip6_address_t), route_oif, l,
					 reason);
    case SEG6_LOCAL_ACTION_END_DX4:
      l->action = LCP_NL_SRV6_ACTION_END_DX4;
      return lcp_nl_srv6_parse_xconnect (tb, SEG6_LOCAL_NH4, sizeof (ip4_address_t), route_oif, l,
					 reason);
    case SEG6_LOCAL_ACTION_END_T:
      l->action = LCP_NL_SRV6_ACTION_END_T;
      return lcp_nl_srv6_parse_table (tb[SEG6_LOCAL_TABLE], l, reason);
    case SEG6_LOCAL_ACTION_END_DT6:
      /* "table" is the legacy mode without a VRF device; both look up a table */
      l->action = LCP_NL_SRV6_ACTION_END_DT6;
      return lcp_nl_srv6_parse_table (
	tb[SEG6_LOCAL_VRFTABLE] ? tb[SEG6_LOCAL_VRFTABLE] : tb[SEG6_LOCAL_TABLE], l, reason);
    case SEG6_LOCAL_ACTION_END_DT4:
      l->action = LCP_NL_SRV6_ACTION_END_DT4;
      return lcp_nl_srv6_parse_table (tb[SEG6_LOCAL_VRFTABLE], l, reason);
    case SEG6_LOCAL_ACTION_END_DT46:
      l->action = LCP_NL_SRV6_ACTION_END_DT46;
      return lcp_nl_srv6_parse_table (tb[SEG6_LOCAL_VRFTABLE], l, reason);
    default:
      return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_UNSUPPORTED, "seg6local action %u",
			       action);
    }
}

static lcp_nl_srv6_parse_rc_t
lcp_nl_srv6_parse_route (const struct rtmsg *rtm, struct nlattr **tb, lcp_nl_srv6_nh_t *nhs,
			 u32 n_encap, u32 n_local, lcp_nl_srv6_route_t *route, u8 **reason)
{
  lcp_nl_srv6_parse_rc_t rc;
  lcp_nl_srv6_nh_t *nh;

  route->table_id = tb[RTA_TABLE] ? nla_get_u32 (tb[RTA_TABLE]) : rtm->rtm_table;
  route->protocol = rtm->rtm_protocol;
  route->priority = tb[RTA_PRIORITY] ? nla_get_u32 (tb[RTA_PRIORITY]) : 0;

  rc = lcp_nl_srv6_parse_prefix (rtm, tb, &route->prefix, reason);
  if (rc != LCP_NL_SRV6_PARSE_OK)
    return rc;

  if (n_encap + n_local != vec_len (nhs) || (n_encap && n_local))
    return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_UNSUPPORTED,
			     "SRv6 and other next hops in one route");
  if (rtm->rtm_type != RTN_UNICAST)
    return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_UNSUPPORTED, "route type %u", rtm->rtm_type);
  if (rtm->rtm_src_len)
    return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_UNSUPPORTED, "source prefix");

  if (n_local)
    {
      if (n_local > 1)
	return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_UNSUPPORTED,
				 "local SID with %u next hops", n_local);
      if (route->prefix.fp_proto != FIB_PROTOCOL_IP6)
	return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_MALFORMED, "IPv4 local SID");

      route->kind = LCP_NL_SRV6_ROUTE_LOCAL;
      return lcp_nl_srv6_parse_local (nhs[0].encap, nhs[0].ifindex, &route->local, reason);
    }

  route->kind = LCP_NL_SRV6_ROUTE_ENCAP;
  vec_foreach (nh, nhs)
    {
      lcp_nl_srv6_encap_t *e;

      vec_add2 (route->encaps, e, 1);
      e->weight = nh->weight;
      rc = lcp_nl_srv6_parse_encap (nh->encap, e, reason);
      if (rc != LCP_NL_SRV6_PARSE_OK)
	return rc;
    }

  return LCP_NL_SRV6_PARSE_OK;
}

lcp_nl_srv6_parse_rc_t
lcp_nl_srv6_route_parse (const struct nlmsghdr *nlh, lcp_nl_srv6_route_t *route, u8 **reason)
{
  struct nlattr *tb[RTA_MAX + 1];
  lcp_nl_srv6_nh_t *nhs = NULL, *nh;
  lcp_nl_srv6_parse_rc_t rc;
  u32 n_encap = 0, n_local = 0;

  clib_memset (route, 0, sizeof (*route));

  if (nlh->nlmsg_type != RTM_NEWROUTE && nlh->nlmsg_type != RTM_DELROUTE)
    return LCP_NL_SRV6_PARSE_NOT_SRV6;

  if (nlmsg_parse ((struct nlmsghdr *) nlh, sizeof (struct rtmsg), tb, RTA_MAX, NULL) < 0)
    return lcp_nl_srv6_fail (reason, LCP_NL_SRV6_PARSE_MALFORMED, "route message does not parse");

  rc = lcp_nl_srv6_parse_nhs (tb, &nhs, reason);
  if (rc != LCP_NL_SRV6_PARSE_OK)
    goto done;

  vec_foreach (nh, nhs)
    {
      switch (lcp_nl_srv6_nh_encap_type (nh))
	{
	case LWTUNNEL_ENCAP_SEG6:
	  n_encap++;
	  break;
	case LWTUNNEL_ENCAP_SEG6_LOCAL:
	  n_local++;
	  break;
	}
    }

  if (n_encap + n_local == 0)
    rc = LCP_NL_SRV6_PARSE_NOT_SRV6;
  else
    rc = lcp_nl_srv6_parse_route (nlmsg_data (nlh), tb, nhs, n_encap, n_local, route, reason);

done:
  vec_free (nhs);
  if (rc != LCP_NL_SRV6_PARSE_OK)
    lcp_nl_srv6_route_free (route);

  return rc;
}

void
lcp_nl_srv6_route_free (lcp_nl_srv6_route_t *route)
{
  lcp_nl_srv6_encap_t *e;

  vec_foreach (e, route->encaps)
    vec_free (e->segments);
  vec_free (route->encaps);
}

u8 *
format_lcp_nl_srv6_segments (u8 *s, va_list *args)
{
  ip6_address_t *segments = va_arg (*args, ip6_address_t *);
  ip6_address_t *segment;

  s = format (s, "[");
  vec_foreach (segment, segments)
    s = format (s, "%s%U", segment == segments ? "" : ", ", format_ip6_address, segment);

  return format (s, "]");
}

static const char *lcp_nl_srv6_action_names[] = {
  [LCP_NL_SRV6_ACTION_END] = "End",	    [LCP_NL_SRV6_ACTION_END_X] = "End.X",
  [LCP_NL_SRV6_ACTION_END_T] = "End.T",	    [LCP_NL_SRV6_ACTION_END_DX4] = "End.DX4",
  [LCP_NL_SRV6_ACTION_END_DX6] = "End.DX6", [LCP_NL_SRV6_ACTION_END_DT4] = "End.DT4",
  [LCP_NL_SRV6_ACTION_END_DT6] = "End.DT6", [LCP_NL_SRV6_ACTION_END_DT46] = "End.DT46",
};

u8 *
format_lcp_nl_srv6_route (u8 *s, va_list *args)
{
  lcp_nl_srv6_route_t *route = va_arg (*args, lcp_nl_srv6_route_t *);
  const lcp_nl_srv6_local_t *l = &route->local;
  lcp_nl_srv6_encap_t *e;

  s = format (s, "table %u %U", route->table_id, format_fib_prefix, &route->prefix);

  if (route->kind == LCP_NL_SRV6_ROUTE_ENCAP)
    {
      vec_foreach (e, route->encaps)
	s = format (s, " encap%s segs %U weight %u",
		    e->mode == LCP_NL_SRV6_ENCAP_MODE_ENCAP_RED ? ".red" : "",
		    format_lcp_nl_srv6_segments, e->segments, e->weight);
      return s;
    }

  s = format (s, " %s", lcp_nl_srv6_action_names[l->action]);
  if (l->next_csid)
    s = format (s, " next-csid lblen %u nflen %u", l->lcblock_bits, l->lcnode_fn_bits);

  switch (l->action)
    {
    case LCP_NL_SRV6_ACTION_END_X:
    case LCP_NL_SRV6_ACTION_END_DX6:
      s = format (s, " nh6 %U oif %u", format_ip6_address, &l->nh.ip6, l->oif);
      break;
    case LCP_NL_SRV6_ACTION_END_DX4:
      s = format (s, " nh4 %U oif %u", format_ip4_address, &l->nh.ip4, l->oif);
      break;
    case LCP_NL_SRV6_ACTION_END_T:
    case LCP_NL_SRV6_ACTION_END_DT4:
    case LCP_NL_SRV6_ACTION_END_DT6:
    case LCP_NL_SRV6_ACTION_END_DT46:
      s = format (s, " table %u", l->table_id);
      break;
    case LCP_NL_SRV6_ACTION_END:
      break;
    }

  return s;
}
