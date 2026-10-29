/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 as38656
 */

/*
 * Path MTU of SRv6 encaps segment lists.
 *
 * An encapsulated packet goes to the first segment of its segment list,
 * looked up in the egress table of the segment list. The segment list tracks
 * the FIB entry of the first segment and keeps the MTU of the path to it.
 * This is the MTU of the forwarding of the entry (dpo_get_mtu ()): the
 * smallest IPv6 MTU of the adjacencies of all its paths. It also follows
 * the path MTUs set with the ip_path_mtu_update API.
 *
 * A FIB back walk updates the value. A route change walks back to the
 * tracked entry at once. An interface MTU change updates the adjacencies of
 * the interface and walks back from them a little later (adj_mtu_update ()).
 *
 * The headend nodes compare each inner packet with inner_mtu before they
 * encapsulate it (see sr_policy_rewrite.c).
 */

#include <vnet/srv6/sr.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_entry_track.h>
#include <vnet/dpo/dpo.h>

/*
 * ip6-rewrite does not check an MTU below the IPv6 minimum link MTU, so the
 * headend does not check it either. It never drops a packet that ip6-rewrite
 * would send.
 */
#define SR_PATH_MTU_MIN 1280

static fib_node_type_t sr_sl_pmtu_node_type;

static ip6_sr_sl_t *
sr_sl_from_pmtu_node (fib_node_t *node)
{
  return ((ip6_sr_sl_t *) (((char *) node) - STRUCT_OFFSET_OF (ip6_sr_sl_t, pmtu_node)));
}

static void
sr_sl_path_mtu_update (ip6_sr_sl_t *sl)
{
  const dpo_id_t *dpo;
  u32 encap_len;
  u16 mtu;

  dpo = fib_entry_contribute_ip_forwarding (sl->pmtu_fib_entry);
  mtu = dpo_get_mtu (dpo);
  encap_len = vec_len (sl->rewrite);

  /* 0xffff means that no path has an MTU, e.g. the segment is unreachable */
  if (mtu == 0xffff || mtu < SR_PATH_MTU_MIN)
    {
      sl->path_mtu = 0;
      sl->inner_mtu = ~0;
      return;
    }

  sl->path_mtu = mtu;
  sl->inner_mtu = mtu > encap_len ? mtu - encap_len : 0;
}

void
sr_sl_path_mtu_track (ip6_sr_sl_t *sl)
{
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = 128,
    .fp_addr = {
      .ip6 = sl->segments[0],
    },
  };

  fib_node_init (&sl->pmtu_node, sr_sl_pmtu_node_type);
  sl->pmtu_fib_entry = fib_entry_track (sl->egress_fib_table, &pfx, sr_sl_pmtu_node_type,
					sl - sr_main.sid_lists, &sl->pmtu_sibling);
  sr_sl_path_mtu_update (sl);
}

void
sr_sl_path_mtu_untrack (ip6_sr_sl_t *sl)
{
  if (FIB_NODE_INDEX_INVALID == sl->pmtu_fib_entry)
    return;

  fib_entry_untrack (sl->pmtu_fib_entry, sl->pmtu_sibling);
  fib_node_deinit (&sl->pmtu_node);
  sl->pmtu_fib_entry = FIB_NODE_INDEX_INVALID;
  sl->path_mtu = 0;
  sl->inner_mtu = ~0;
}

u8 *
format_sr_sl_path_mtu (u8 *s, va_list *args)
{
  ip6_sr_sl_t *sl = va_arg (*args, ip6_sr_sl_t *);

  if (0 == sl->path_mtu)
    return format (s, "path MTU: none");

  return format (s, "path MTU: %u, inner MTU: %u", sl->path_mtu, sl->inner_mtu);
}

static fib_node_t *
sr_sl_pmtu_get_node (fib_node_index_t index)
{
  ip6_sr_sl_t *sl = pool_elt_at_index (sr_main.sid_lists, index);

  return &sl->pmtu_node;
}

static void
sr_sl_pmtu_last_lock_gone (fib_node_t *node)
{
  /* The SR policies own their segment lists. The FIB never locks them. */
  ASSERT (0);
}

static fib_node_back_walk_rc_t
sr_sl_pmtu_back_walk_notify (fib_node_t *node, fib_node_back_walk_ctx_t *ctx)
{
  sr_sl_path_mtu_update (sr_sl_from_pmtu_node (node));

  return FIB_NODE_BACK_WALK_CONTINUE;
}

static const fib_node_vft_t sr_sl_pmtu_vft = {
  .fnv_get = sr_sl_pmtu_get_node,
  .fnv_last_lock = sr_sl_pmtu_last_lock_gone,
  .fnv_back_walk = sr_sl_pmtu_back_walk_notify,
};

static clib_error_t *
sr_path_mtu_init (vlib_main_t *vm)
{
  sr_sl_pmtu_node_type = fib_node_register_new_type ("sr-sl-path-mtu", &sr_sl_pmtu_vft);

  return 0;
}

VLIB_INIT_FUNCTION (sr_path_mtu_init);
