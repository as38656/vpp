/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 as38656
 */

/*
 * Programs the SRv6 routes of the kernel into VPP.
 *
 * An encapsulation route becomes a FIB entry with one exclusive path per
 * next hop. The path points at the DPO of an SR policy that holds the
 * segment list. Routes with the same segment list share the policy. The
 * entry uses the FIB source of the other kernel routes, so a route that
 * changes between SRv6 and a plain next hop only replaces its paths.
 *
 * A local SID becomes an SR localsid.
 */

#include <linux/rtnetlink.h>

#include <vlib/vlib.h>
#include <vnet/fib/fib_table.h>
#include <vnet/srv6/sr.h>

#include <linux-cp/lcp_nl.h>
#include <linux-cp/lcp_router.h>

typedef struct lcp_srv6_key_t_
{
  ip46_address_t addr;
  u32 table_id;
  u8 len;
  u8 proto;
  u8 pad[2];
} lcp_srv6_key_t;

typedef struct lcp_srv6_policy_t_
{
  /* Segment list (vector). The key of the policy. */
  ip6_address_t *segments;
  ip6_address_t bsid;
  u32 n_locks;
} lcp_srv6_policy_t;

typedef struct lcp_srv6_route_path_t_
{
  index_t policy;
  u8 weight;
  u8 preference;
} lcp_srv6_route_path_t;

/* The SRv6 paths of a prefix in a VPP table */
typedef struct lcp_srv6_route_t_
{
  lcp_srv6_key_t key;
  fib_prefix_t pfx;
  u32 fib_index;
  fib_source_t source;
  lcp_srv6_route_path_t *paths;
  u8 stale;
} lcp_srv6_route_t;

typedef struct lcp_srv6_localsid_t_
{
  lcp_srv6_key_t key;
  /* What the kernel asked for, to compare against a later message */
  lcp_nl_srv6_local_t local;
  /* Kernel ids of the tables that this localsid keeps */
  u32 sid_table_id;
  u32 lookup_table_id;
  u8 lookup_ip4;
  u8 lookup_ip6;
  u8 stale;
} lcp_srv6_localsid_t;

typedef struct lcp_srv6_main_t_
{
  ip6_address_t bsid_prefix;
  u8 bsid_prefix_len;
  u8 has_bsid_prefix;
  ip6_address_t encap_source;
  u8 has_encap_source;

  lcp_srv6_policy_t *policies;
  uword *policy_by_segments;

  lcp_srv6_route_t *routes;
  mhash_t route_by_key;

  lcp_srv6_localsid_t *localsids;
  mhash_t localsid_by_key;

  vlib_log_class_t logger;
} lcp_srv6_main_t;

static lcp_srv6_main_t lcp_srv6_main;

#define LCP_SRV6_DBG(...)   vlib_log_debug (lcp_srv6_main.logger, __VA_ARGS__);
#define LCP_SRV6_INFO(...)  vlib_log_notice (lcp_srv6_main.logger, __VA_ARGS__);
#define LCP_SRV6_ERROR(...) vlib_log_err (lcp_srv6_main.logger, __VA_ARGS__);

static void
lcp_srv6_mk_key (lcp_srv6_key_t *key, u32 table_id, const fib_prefix_t *pfx)
{
  clib_memset (key, 0, sizeof (*key));
  key->addr = pfx->fp_addr;
  key->table_id = table_id;
  key->len = pfx->fp_len;
  key->proto = pfx->fp_proto;
}

static ip6_address_t
lcp_srv6_bsid (index_t policy)
{
  ip6_address_t bsid = lcp_srv6_main.bsid_prefix;

  bsid.as_u32[3] = clib_host_to_net_u32 (clib_net_to_host_u32 (bsid.as_u32[3]) + policy + 1);

  return bsid;
}

static ip6_sr_policy_t *
lcp_srv6_sr_policy (index_t policy)
{
  lcp_srv6_policy_t *lp = pool_elt_at_index (lcp_srv6_main.policies, policy);
  uword *p = mhash_get (&sr_main.sr_policies_index_hash, &lp->bsid);

  return pool_elt_at_index (sr_main.sr_policies, p[0]);
}

static index_t
lcp_srv6_policy_find (ip6_address_t *segments)
{
  uword *p = hash_get_mem (lcp_srv6_main.policy_by_segments, segments);

  return p ? p[0] : INDEX_INVALID;
}

static index_t
lcp_srv6_policy_lock (ip6_address_t *segments)
{
  lcp_srv6_main_t *lsm = &lcp_srv6_main;
  vlib_main_t *vm = vlib_get_main ();
  lcp_srv6_policy_t *lp;
  index_t policy;
  int rv;

  policy = lcp_srv6_policy_find (segments);
  if (INDEX_INVALID != policy)
    {
      pool_elt_at_index (lsm->policies, policy)->n_locks++;
      return policy;
    }

  pool_get_zero (lsm->policies, lp);
  policy = lp - lsm->policies;
  lp->segments = vec_dup (segments);
  lp->bsid = lcp_srv6_bsid (policy);

  /* workers read the policy and segment list pools */
  vlib_worker_thread_barrier_sync (vm);
  rv = sr_policy_add (&lp->bsid, lp->segments, &lsm->encap_source, SR_SEGMENT_LIST_WEIGHT_DEFAULT,
		      SR_POLICY_TYPE_DEFAULT, 0, 1, 0, NULL);
  vlib_worker_thread_barrier_release (vm);

  if (rv)
    {
      LCP_SRV6_ERROR ("SR policy %U for segments %U not created: %d", format_ip6_address, &lp->bsid,
		      format_lcp_nl_srv6_segments, lp->segments, rv);
      vec_free (lp->segments);
      pool_put (lsm->policies, lp);
      return INDEX_INVALID;
    }

  LCP_SRV6_DBG ("SR policy %U for segments %U", format_ip6_address, &lp->bsid,
		format_lcp_nl_srv6_segments, lp->segments);
  hash_set_mem (lsm->policy_by_segments, lp->segments, policy);
  lp->n_locks = 1;

  return policy;
}

static void
lcp_srv6_policy_unlock (index_t policy)
{
  lcp_srv6_main_t *lsm = &lcp_srv6_main;
  vlib_main_t *vm = vlib_get_main ();
  lcp_srv6_policy_t *lp = pool_elt_at_index (lsm->policies, policy);

  if (--lp->n_locks)
    return;

  LCP_SRV6_DBG ("SR policy %U removed", format_ip6_address, &lp->bsid);
  hash_unset_mem (lsm->policy_by_segments, lp->segments);

  vlib_worker_thread_barrier_sync (vm);
  sr_policy_del (&lp->bsid, ~0);
  vlib_worker_thread_barrier_release (vm);

  vec_free (lp->segments);
  pool_put (lsm->policies, lp);
}

static void
lcp_srv6_paths_unlock (const lcp_srv6_route_path_t *paths)
{
  const lcp_srv6_route_path_t *path;

  vec_foreach (path, paths)
    lcp_srv6_policy_unlock (path->policy);
}

static int
lcp_srv6_paths_equal (const lcp_srv6_route_path_t *a, const lcp_srv6_route_path_t *b)
{
  u32 i;

  if (vec_len (a) != vec_len (b))
    return 0;
  for (i = 0; i < vec_len (a); i++)
    if (a[i].policy != b[i].policy || a[i].weight != b[i].weight ||
	a[i].preference != b[i].preference)
      return 0;

  return 1;
}

static fib_route_path_t *
lcp_srv6_fib_paths (const lcp_srv6_route_path_t *paths, fib_protocol_t fproto)
{
  const lcp_srv6_route_path_t *path;
  fib_route_path_t *rpaths = NULL, *rpath;

  vec_foreach (path, paths)
    {
      ip6_sr_policy_t *sp = lcp_srv6_sr_policy (path->policy);

      vec_add2 (rpaths, rpath, 1);
      clib_memset (rpath, 0, sizeof (*rpath));
      rpath->frp_proto = fib_proto_to_dpo (fproto);
      rpath->frp_flags = FIB_ROUTE_PATH_EXCLUSIVE;
      rpath->frp_sw_if_index = ~0;
      rpath->frp_fib_index = ~0;
      rpath->frp_weight = path->weight;
      rpath->frp_preference = path->preference;
      /* fib_path_create reads the exclusive DPO from dpo, not from frp_dpo */
      rpath->dpo = (fproto == FIB_PROTOCOL_IP4) ? sp->ip4_dpo : sp->ip6_dpo;
    }

  return rpaths;
}

/* Remove the paths from the FIB entry and drop their policies */
static void
lcp_srv6_route_remove_paths (lcp_srv6_route_t *lr, lcp_srv6_route_path_t *paths)
{
  fib_route_path_t *rpaths;

  if (0 == vec_len (paths))
    return;

  rpaths = lcp_srv6_fib_paths (paths, lr->pfx.fp_proto);
  fib_table_entry_path_remove2 (lr->fib_index, &lr->pfx, lr->source, rpaths);
  vec_free (rpaths);
  lcp_srv6_paths_unlock (paths);
}

static void
lcp_srv6_route_free (lcp_srv6_route_t *lr)
{
  lcp_srv6_main_t *lsm = &lcp_srv6_main;

  lcp_router_table_unlock (lcp_router_table_find (lr->key.table_id, lr->pfx.fp_proto));
  mhash_unset (&lsm->route_by_key, &lr->key, NULL);
  vec_free (lr->paths);
  pool_put (lsm->routes, lr);
}

static lcp_srv6_route_t *
lcp_srv6_route_find (u32 table_id, const fib_prefix_t *pfx)
{
  lcp_srv6_main_t *lsm = &lcp_srv6_main;
  lcp_srv6_key_t key;
  uword *p;

  lcp_srv6_mk_key (&key, lcp_router_table_k2f (table_id), pfx);
  p = mhash_get (&lsm->route_by_key, &key);

  return p ? pool_elt_at_index (lsm->routes, p[0]) : NULL;
}

static lcp_srv6_route_t *
lcp_srv6_route_create (const lcp_nl_srv6_route_t *route, fib_source_t source)
{
  lcp_srv6_main_t *lsm = &lcp_srv6_main;
  lcp_router_table_t *nlt;
  lcp_srv6_route_t *lr;

  nlt = lcp_router_table_add_or_lock (route->table_id, route->prefix.fp_proto);

  pool_get_zero (lsm->routes, lr);
  lcp_srv6_mk_key (&lr->key, nlt->nlt_id, &route->prefix);
  lr->pfx = route->prefix;
  lr->fib_index = nlt->nlt_fib_index;
  lr->source = source;
  mhash_set (&lsm->route_by_key, &lr->key, lr - lsm->routes, NULL);

  return lr;
}

static void
lcp_srv6_encap_add (const lcp_nl_srv6_route_t *route, int is_replace)
{
  lcp_srv6_main_t *lsm = &lcp_srv6_main;
  lcp_srv6_route_path_t *paths = NULL, *old_paths;
  const lcp_nl_srv6_encap_t *e;
  fib_route_path_t *rpaths;
  fib_entry_flag_t flags;
  fib_source_t source;
  lcp_srv6_route_t *lr;

  if (!lsm->has_bsid_prefix || !lsm->has_encap_source)
    {
      LCP_SRV6_ERROR ("route %U not synced: linux-nl-srv6 needs bsid-prefix and encap-source",
		      format_lcp_nl_srv6_route, route);
      return;
    }

  vec_foreach (e, route->encaps)
    {
      lcp_srv6_route_path_t path = {
	.policy = lcp_srv6_policy_lock (e->segments),
	/* the FIB weight is one byte and the kernel weight goes up to 256 */
	.weight = clib_min (e->weight, 255),
	.preference = (u8) route->priority,
      };

      if (INDEX_INVALID == path.policy)
	{
	  LCP_SRV6_ERROR ("route %U not synced", format_lcp_nl_srv6_route, route);
	  lcp_srv6_paths_unlock (paths);
	  vec_free (paths);
	  return;
	}
      vec_add1 (paths, path);
    }

  source = lcp_router_proto_fib_source (route->protocol);
  lr = lcp_srv6_route_find (route->table_id, &route->prefix);

  if (lr && lr->source != source)
    {
      /* the kernel route moved to another protocol */
      lcp_srv6_route_remove_paths (lr, lr->paths);
      lcp_srv6_route_free (lr);
      lr = NULL;
    }

  if (!lr)
    lr = lcp_srv6_route_create (route, source);
  else if (lr->stale)
    /* the dump of a resync has the whole state of the prefix */
    is_replace = 1;
  else if (is_replace && lcp_srv6_paths_equal (lr->paths, paths))
    {
      /*
       * The kernel replaces every route of a nexthop object when the object
       * changes, often only in its IGP next hop, which VPP resolves itself.
       */
      lcp_srv6_paths_unlock (paths);
      vec_free (paths);
      return;
    }

  LCP_SRV6_DBG ("route %s: %U", is_replace ? "replace" : "add", format_lcp_nl_srv6_route, route);

  flags = lcp_router_route_mk_entry_flags (RTN_UNICAST, route->table_id, route->protocol);
  rpaths = lcp_srv6_fib_paths (paths, route->prefix.fp_proto);
  if (is_replace)
    fib_table_entry_update (lr->fib_index, &lr->pfx, source, flags, rpaths);
  else
    fib_table_entry_path_add2 (lr->fib_index, &lr->pfx, source, flags, rpaths);
  vec_free (rpaths);

  if (is_replace)
    {
      old_paths = lr->paths;
      lr->paths = paths;
      lcp_srv6_paths_unlock (old_paths);
      vec_free (old_paths);
    }
  else
    {
      vec_append (lr->paths, paths);
      vec_free (paths);
    }
  lr->stale = 0;
}

static void
lcp_srv6_encap_del (const lcp_nl_srv6_route_t *route)
{
  lcp_srv6_route_path_t *removed = NULL, *path;
  const lcp_nl_srv6_encap_t *e;
  lcp_srv6_route_t *lr;

  lr = lcp_srv6_route_find (route->table_id, &route->prefix);
  if (!lr)
    {
      LCP_SRV6_DBG ("route del: %U is not known", format_lcp_nl_srv6_route, route);
      return;
    }

  LCP_SRV6_DBG ("route del: %U", format_lcp_nl_srv6_route, route);

  vec_foreach (e, route->encaps)
    {
      index_t policy = lcp_srv6_policy_find (e->segments);
      u8 weight = clib_min (e->weight, 255);

      vec_foreach (path, lr->paths)
	{
	  if (path->policy == policy && path->weight == weight &&
	      path->preference == (u8) route->priority)
	    {
	      vec_add1 (removed, *path);
	      vec_del1 (lr->paths, path - lr->paths);
	      break;
	    }
	}
    }

  if (vec_len (removed) != vec_len (route->encaps))
    LCP_SRV6_ERROR ("route del: %U: %u of %u paths are not known", format_lcp_nl_srv6_route, route,
		    vec_len (route->encaps) - vec_len (removed), vec_len (route->encaps));

  lcp_srv6_route_remove_paths (lr, removed);
  vec_free (removed);

  if (0 == vec_len (lr->paths))
    lcp_srv6_route_free (lr);
}

void
lcp_router_srv6_route_replaced (u32 table_id, const fib_prefix_t *pfx)
{
  lcp_srv6_route_t *lr = lcp_srv6_route_find (table_id, pfx);

  if (!lr)
    return;

  LCP_SRV6_DBG ("route replaced without SRv6: table %u %U", table_id, format_fib_prefix, pfx);

  /* a no-op when the plain route has the same source, which replaced the paths */
  lcp_srv6_route_remove_paths (lr, lr->paths);
  lcp_srv6_route_free (lr);
}

/*
 * The VPP behavior of a local SID. Sets the interface or table argument,
 * the next hop and the uSID length of sr_cli_localsid.
 */
static int
lcp_srv6_local_behavior (const lcp_nl_srv6_route_t *route, u8 *behavior, u32 *arg,
			 ip46_address_t *nh, int *usid_len)
{
  const lcp_nl_srv6_local_t *l = &route->local;

  *arg = ~0;
  *usid_len = 0;
  *nh = l->nh;

  if (l->next_csid)
    {
      if (l->lcnode_fn_bits != 16 && l->lcnode_fn_bits != 32)
	return -1;
      if (l->lcblock_bits % 8 || route->prefix.fp_len != l->lcblock_bits + l->lcnode_fn_bits)
	return -1;
      *usid_len = l->lcnode_fn_bits;
    }

  switch (l->action)
    {
    case LCP_NL_SRV6_ACTION_END:
      /* End.uN, which goes on with the SRH when no C-SID is left, as RFC 9800 says */
      *behavior = l->next_csid ? SR_BEHAVIOR_END_UN : SR_BEHAVIOR_END;
      return 0;
    case LCP_NL_SRV6_ACTION_END_X:
      *behavior = l->next_csid ? SR_BEHAVIOR_UA : SR_BEHAVIOR_X;
      *arg = lcp_router_intf_h2p (l->oif);
      return (~0 == *arg) ? -2 : 0;
    case LCP_NL_SRV6_ACTION_END_DX4:
      *behavior = SR_BEHAVIOR_DX4;
      *arg = lcp_router_intf_h2p (l->oif);
      return (~0 == *arg) ? -2 : 0;
    case LCP_NL_SRV6_ACTION_END_DX6:
      *behavior = SR_BEHAVIOR_DX6;
      *arg = lcp_router_intf_h2p (l->oif);
      return (~0 == *arg) ? -2 : 0;
    case LCP_NL_SRV6_ACTION_END_T:
      *behavior = SR_BEHAVIOR_T;
      break;
    case LCP_NL_SRV6_ACTION_END_DT4:
      *behavior = SR_BEHAVIOR_DT4;
      break;
    case LCP_NL_SRV6_ACTION_END_DT6:
      *behavior = SR_BEHAVIOR_DT6;
      break;
    case LCP_NL_SRV6_ACTION_END_DT46:
      *behavior = SR_BEHAVIOR_DT46;
      break;
    }

  *arg = lcp_router_table_k2f (l->table_id);
  return 0;
}

static void
lcp_srv6_localsid_tables_unlock (const lcp_srv6_localsid_t *ls)
{
  u32 lookup_table = lcp_router_table_k2f (ls->lookup_table_id);

  lcp_router_table_unlock (
    lcp_router_table_find (lcp_router_table_k2f (ls->sid_table_id), FIB_PROTOCOL_IP6));
  if (ls->lookup_ip4)
    lcp_router_table_unlock (lcp_router_table_find (lookup_table, FIB_PROTOCOL_IP4));
  if (ls->lookup_ip6)
    lcp_router_table_unlock (lcp_router_table_find (lookup_table, FIB_PROTOCOL_IP6));
}

static void
lcp_srv6_localsid_delete (lcp_srv6_localsid_t *ls)
{
  lcp_srv6_main_t *lsm = &lcp_srv6_main;
  vlib_main_t *vm = vlib_get_main ();
  int rv;

  vlib_worker_thread_barrier_sync (vm);
  rv =
    sr_cli_localsid (1, &ls->key.addr.ip6, ls->key.len, 0, 0, ~0, ls->key.table_id, NULL, 0, NULL);
  vlib_worker_thread_barrier_release (vm);

  if (rv)
    LCP_SRV6_ERROR ("localsid %U/%u in table %u not removed: %d", format_ip6_address,
		    &ls->key.addr.ip6, ls->key.len, ls->key.table_id, rv);

  lcp_srv6_localsid_tables_unlock (ls);
  mhash_unset (&lsm->localsid_by_key, &ls->key, NULL);
  pool_put (lsm->localsids, ls);
}

static lcp_srv6_localsid_t *
lcp_srv6_localsid_find (const lcp_nl_srv6_route_t *route)
{
  lcp_srv6_main_t *lsm = &lcp_srv6_main;
  lcp_srv6_key_t key;
  uword *p;

  lcp_srv6_mk_key (&key, lcp_router_table_k2f (route->table_id), &route->prefix);
  p = mhash_get (&lsm->localsid_by_key, &key);

  return p ? pool_elt_at_index (lsm->localsids, p[0]) : NULL;
}

static void
lcp_srv6_local_add (const lcp_nl_srv6_route_t *route)
{
  lcp_srv6_main_t *lsm = &lcp_srv6_main;
  vlib_main_t *vm = vlib_get_main ();
  const lcp_nl_srv6_local_t *l = &route->local;
  lcp_srv6_localsid_t *ls;
  ip46_address_t nh;
  int usid_len, rv;
  u8 behavior;
  u32 arg;

  ls = lcp_srv6_localsid_find (route);
  if (ls)
    {
      if (0 == memcmp (&ls->local, l, sizeof (*l)))
	{
	  ls->stale = 0;
	  return;
	}
      /* VPP has one localsid per prefix, the last one from the kernel wins */
      lcp_srv6_localsid_delete (ls);
    }

  switch (lcp_srv6_local_behavior (route, &behavior, &arg, &nh, &usid_len))
    {
    case 0:
      break;
    case -1:
      LCP_SRV6_ERROR ("local SID %U not synced: C-SID lengths do not fit VPP",
		      format_lcp_nl_srv6_route, route);
      return;
    default:
      LCP_SRV6_ERROR ("local SID %U not synced: interface %u has no pair", format_lcp_nl_srv6_route,
		      route, l->oif);
      return;
    }

  pool_get_zero (lsm->localsids, ls);
  lcp_srv6_mk_key (&ls->key, lcp_router_table_k2f (route->table_id), &route->prefix);
  clib_memcpy (&ls->local, l, sizeof (*l));
  ls->sid_table_id = route->table_id;
  ls->lookup_table_id = l->table_id;
  ls->lookup_ip4 = (behavior == SR_BEHAVIOR_DT4 || behavior == SR_BEHAVIOR_DT46);
  ls->lookup_ip6 =
    (behavior == SR_BEHAVIOR_DT6 || behavior == SR_BEHAVIOR_DT46 || behavior == SR_BEHAVIOR_T);

  lcp_router_table_add_or_lock (ls->sid_table_id, FIB_PROTOCOL_IP6);
  if (ls->lookup_ip4)
    lcp_router_table_add_or_lock (ls->lookup_table_id, FIB_PROTOCOL_IP4);
  if (ls->lookup_ip6)
    lcp_router_table_add_or_lock (ls->lookup_table_id, FIB_PROTOCOL_IP6);

  vlib_worker_thread_barrier_sync (vm);
  rv = sr_cli_localsid (0, &ls->key.addr.ip6, ls->key.len, 0, behavior, arg, ls->key.table_id, &nh,
			usid_len, NULL);
  vlib_worker_thread_barrier_release (vm);

  if (rv)
    {
      LCP_SRV6_ERROR ("local SID %U not synced: sr localsid error %d", format_lcp_nl_srv6_route,
		      route, rv);
      lcp_srv6_localsid_tables_unlock (ls);
      pool_put (lsm->localsids, ls);
      return;
    }

  LCP_SRV6_DBG ("local SID add: %U", format_lcp_nl_srv6_route, route);
  mhash_set (&lsm->localsid_by_key, &ls->key, ls - lsm->localsids, NULL);
}

static void
lcp_srv6_local_del (const lcp_nl_srv6_route_t *route)
{
  lcp_srv6_localsid_t *ls = lcp_srv6_localsid_find (route);

  if (!ls)
    {
      LCP_SRV6_DBG ("local SID del: %U is not known", format_lcp_nl_srv6_route, route);
      return;
    }
  if (memcmp (&ls->local, &route->local, sizeof (route->local)))
    {
      LCP_SRV6_ERROR ("local SID del: %U is not the SID in VPP", format_lcp_nl_srv6_route, route);
      return;
    }

  LCP_SRV6_DBG ("local SID del: %U", format_lcp_nl_srv6_route, route);
  lcp_srv6_localsid_delete (ls);
}

static void
lcp_srv6_route_add (const lcp_nl_srv6_route_t *route, int is_replace)
{
  if (route->kind == LCP_NL_SRV6_ROUTE_ENCAP)
    lcp_srv6_encap_add (route, is_replace);
  else
    lcp_srv6_local_add (route);
}

static void
lcp_srv6_route_del (const lcp_nl_srv6_route_t *route)
{
  if (route->kind == LCP_NL_SRV6_ROUTE_ENCAP)
    lcp_srv6_encap_del (route);
  else
    lcp_srv6_local_del (route);
}

static void
lcp_srv6_route_sync_begin (void)
{
  lcp_srv6_main_t *lsm = &lcp_srv6_main;
  lcp_srv6_localsid_t *ls;
  lcp_srv6_route_t *lr;

  pool_foreach (lr, lsm->routes)
    lr->stale = 1;
  pool_foreach (ls, lsm->localsids)
    ls->stale = 1;

  LCP_SRV6_INFO ("Begin synchronization of %u SRv6 routes and %u local SIDs",
		 pool_elts (lsm->routes), pool_elts (lsm->localsids));
}

static void
lcp_srv6_route_sync_end (void)
{
  lcp_srv6_main_t *lsm = &lcp_srv6_main;
  index_t *stale = NULL, *index;
  lcp_srv6_localsid_t *ls;
  lcp_srv6_route_t *lr;

  pool_foreach (lr, lsm->routes)
    if (lr->stale)
      vec_add1 (stale, lr - lsm->routes);
  vec_foreach (index, stale)
    {
      lr = pool_elt_at_index (lsm->routes, *index);
      lcp_srv6_route_remove_paths (lr, lr->paths);
      lcp_srv6_route_free (lr);
    }
  vec_reset_length (stale);

  pool_foreach (ls, lsm->localsids)
    if (ls->stale)
      vec_add1 (stale, ls - lsm->localsids);
  vec_foreach (index, stale)
    lcp_srv6_localsid_delete (pool_elt_at_index (lsm->localsids, *index));
  vec_free (stale);

  LCP_SRV6_INFO ("End synchronization of SRv6 routes: %u routes and %u local SIDs",
		 pool_elts (lsm->routes), pool_elts (lsm->localsids));
}

static const nl_vft_t lcp_srv6_vft = {
  .nvl_rt_srv6_route_add = { .is_mp_safe = 1, .cb = lcp_srv6_route_add },
  .nvl_rt_srv6_route_del = { .is_mp_safe = 1, .cb = lcp_srv6_route_del },
  .nvl_rt_route_sync_begin = { .is_mp_safe = 0, .cb = lcp_srv6_route_sync_begin },
  .nvl_rt_route_sync_end = { .is_mp_safe = 0, .cb = lcp_srv6_route_sync_end },
};

static clib_error_t *
lcp_srv6_show (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  lcp_srv6_main_t *lsm = &lcp_srv6_main;
  lcp_srv6_localsid_t *ls;
  lcp_srv6_policy_t *lp;

  if (lsm->has_bsid_prefix)
    vlib_cli_output (vm, "bsid-prefix %U/%u", format_ip6_address, &lsm->bsid_prefix,
		     lsm->bsid_prefix_len);
  if (lsm->has_encap_source)
    vlib_cli_output (vm, "encap-source %U", format_ip6_address, &lsm->encap_source);
  vlib_cli_output (vm, "%u routes, %u policies, %u local SIDs", pool_elts (lsm->routes),
		   pool_elts (lsm->policies), pool_elts (lsm->localsids));

  pool_foreach (lp, lsm->policies)
    vlib_cli_output (vm, "policy %U segments %U locks %u", format_ip6_address, &lp->bsid,
		     format_lcp_nl_srv6_segments, lp->segments, lp->n_locks);
  pool_foreach (ls, lsm->localsids)
    vlib_cli_output (vm, "local SID %U/%u table %u", format_ip6_address, &ls->key.addr.ip6,
		     ls->key.len, ls->key.table_id);

  return NULL;
}

VLIB_CLI_COMMAND (lcp_srv6_show_command, static) = {
  .path = "show lcp srv6",
  .short_help = "show lcp srv6",
  .function = lcp_srv6_show,
};

static clib_error_t *
lcp_srv6_config (vlib_main_t *vm, unformat_input_t *input)
{
  lcp_srv6_main_t *lsm = &lcp_srv6_main;
  ip6_address_t mask;
  u32 len;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "bsid-prefix %U/%u", unformat_ip6_address, &lsm->bsid_prefix, &len))
	{
	  /* BSIDs number the policies in the last 32 bits */
	  if (len > 96)
	    return clib_error_return (0, "bsid-prefix must be /96 or shorter");
	  ip6_address_mask_from_width (&mask, len);
	  if (lsm->bsid_prefix.as_u64[0] & ~mask.as_u64[0] ||
	      lsm->bsid_prefix.as_u64[1] & ~mask.as_u64[1])
	    return clib_error_return (0, "bsid-prefix has host bits set");
	  lsm->bsid_prefix_len = len;
	  lsm->has_bsid_prefix = 1;
	}
      else if (unformat (input, "encap-source %U", unformat_ip6_address, &lsm->encap_source))
	lsm->has_encap_source = 1;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  return NULL;
}

VLIB_CONFIG_FUNCTION (lcp_srv6_config, "linux-nl-srv6");

static clib_error_t *
lcp_srv6_init (vlib_main_t *vm)
{
  lcp_srv6_main_t *lsm = &lcp_srv6_main;

  lsm->logger = vlib_log_register_class ("linux-cp", "srv6");
  lsm->policy_by_segments = hash_create_vec (0, sizeof (ip6_address_t), sizeof (uword));
  mhash_init (&lsm->route_by_key, sizeof (uword), sizeof (lcp_srv6_key_t));
  mhash_init (&lsm->localsid_by_key, sizeof (uword), sizeof (lcp_srv6_key_t));

  nl_register_vft (&lcp_srv6_vft);

  return NULL;
}

VLIB_INIT_FUNCTION (lcp_srv6_init) = {
  .runs_after = VLIB_INITS ("lcp_router_init"),
  .runs_before = VLIB_INITS ("lcp_nl_init"),
};
