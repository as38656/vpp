#!/usr/bin/env python3
"""SRv6 headend: path MTU check before encapsulation"""

import re
import time
import unittest

from scapy.layers.inet import ICMP, IP, UDP, IPerror
from scapy.layers.inet6 import (
    ICMPv6PacketTooBig,
    IPerror6,
    IPv6,
    IPv6ExtHdrSegmentRouting,
)
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from asfframework import VppTestRunner
from framework import VppTestCase
from util import reassemble4
from vpp_ip_route import VppIpRoute, VppIpTable, VppRoutePath, find_route
from vpp_srv6 import (
    SRv6PolicySteeringTypes,
    SRv6PolicyType,
    VppSRv6PolicyV2,
    VppSRv6Steering,
)

BSID = "a3::9999:1"
ENCAP_SRC = "a3::"
# a4::/64 is routed out of pg1, a6::/64 out of pg2
SEGMENT = "a4::1"
OTHER_SEGMENT = "a6::1"
# Second segment of a list; it is only carried in the SRH
SRH_SEGMENT = "a5::1"
DST6 = "a7::1"
DST4 = "7.1.1.1"
VRF = 10

DEFAULT_MTU = 9000
EGRESS_MTU = 1400
OTHER_MTU = 1350
IP6_HDR_LEN = 40
# 8 bytes of SRH header and one address for each segment
SRH_2_SEGMENTS_LEN = 8 + 2 * 16
INNER_MTU = EGRESS_MTU - IP6_HDR_LEN

TOO_BIG = "SR: packets too big, ICMP error sent"
FRAGMENTED = "SR: packets fragmented before encaps"
ENCAPS6_NODE = "sr-pl-rewrite-encaps"
ENCAPS4_NODE = "sr-pl-rewrite-encaps-v4"


class TestSRv6EncapsMTU(VppTestCase):
    """SRv6 headend path MTU"""

    @classmethod
    def setUpClass(cls):
        super(TestSRv6EncapsMTU, cls).setUpClass()
        # pg0: ingress in the default table
        # pg1, pg2: egress towards the first segment
        # pg3: ingress in a VRF
        cls.create_pg_interfaces(range(4))

    @classmethod
    def tearDownClass(cls):
        super(TestSRv6EncapsMTU, cls).tearDownClass()

    def setUp(self):
        super(TestSRv6EncapsMTU, self).setUp()

        VppIpTable(self, VRF).add_vpp_config()
        VppIpTable(self, VRF, is_ip6=True).add_vpp_config()
        self.pg3.set_table_ip4(VRF)
        self.pg3.set_table_ip6(VRF)
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.disable_ipv6_ra()
            i.resolve_arp()
            i.resolve_ndp()

        self.route = VppIpRoute(
            self, "a4::", 64, [VppRoutePath(self.pg1.remote_ip6, self.pg1.sw_if_index)]
        )
        self.route.add_vpp_config()
        VppIpRoute(
            self, "a6::", 64, [VppRoutePath(self.pg2.remote_ip6, self.pg2.sw_if_index)]
        ).add_vpp_config()

        # SR objects are removed before the tables and routes they use
        self.sr_objects = []

    def tearDown(self):
        if not self.vpp_dead:
            for obj in reversed(self.sr_objects):
                obj.remove_vpp_config()
            for i in self.pg_interfaces:
                i.set_l3_mtu(DEFAULT_MTU)
                i.unconfig_ip4()
                i.unconfig_ip6()
                i.set_table_ip4(0)
                i.set_table_ip6(0)
                i.admin_down()
        super(TestSRv6EncapsMTU, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show sr policies"))
        self.logger.info(self.vapi.cli("show errors"))

    def add_policy(self, *segment_lists):
        """Add the encaps policy BSID with the segment lists, egress table 0"""
        policy = VppSRv6PolicyV2(
            self,
            bsid=BSID,
            is_encap=1,
            sr_type=SRv6PolicyType.SR_POLICY_TYPE_DEFAULT,
            weight=1,
            fib_table=0,
            encap_src=ENCAP_SRC,
            source=ENCAP_SRC,
        )
        policy.add_vpp_config(segments=list(segment_lists[0]))
        for segments in segment_lists[1:]:
            policy.mod_vpp_config(segments=list(segments))
        self.sr_objects.append(policy)
        self.logger.info(self.vapi.cli("show sr policies"))
        return policy

    def steer(self, table_id=0):
        """Steer DST6 and DST4 in the table into the policy"""
        for prefix, length, traffic_type in (
            ("a7::", 64, SRv6PolicySteeringTypes.SR_STEER_IPV6),
            ("7.1.1.0", 24, SRv6PolicySteeringTypes.SR_STEER_IPV4),
        ):
            steering = VppSRv6Steering(
                self,
                bsid=BSID,
                prefix=prefix,
                mask_width=length,
                traffic_type=traffic_type,
                sr_policy_index=0,
                table_id=table_id,
                sw_if_index=0,
            )
            steering.add_vpp_config()
            self.sr_objects.append(steering)

    def ip6_packet(self, intf, length, sport=1234):
        """IPv6/UDP packet to DST6 with the given IPv6 packet length"""
        return (
            Ether(src=intf.remote_mac, dst=intf.local_mac)
            / IPv6(src=intf.remote_ip6, dst=DST6)
            / UDP(sport=sport, dport=4321)
            / Raw(b"\xa5" * (length - 40 - 8))
        )

    def ip4_packet(self, intf, length, df, ip_id=1):
        """IPv4/UDP packet to DST4 with the given IPv4 packet length"""
        return (
            Ether(src=intf.remote_mac, dst=intf.local_mac)
            / IP(src=intf.remote_ip4, dst=DST4, flags="DF" if df else 0, id=ip_id)
            / UDP(sport=1234, dport=4321)
            / Raw(b"\x5a" * (length - 20 - 8))
        )

    def path_mtu(self, first_segment):
        """The path MTU that show sr policies gives for a segment list"""
        for line in self.vapi.cli("show sr policies").splitlines():
            if "< %s," % first_segment in line:
                m = re.search(r"path MTU: (\w+)", line)
                return m.group(1) if m else None
        return None

    def wait_for_path_mtu(self, first_segment, mtu, timeout=5):
        """Wait until the segment list uses the path MTU (None: no MTU)

        An interface MTU change reaches the segment lists through an
        asynchronous FIB walk.
        """
        expected = "none" if mtu is None else str(mtu)
        deadline = time.time() + timeout
        while True:
            found = self.path_mtu(first_segment)
            if found == expected:
                return
            if time.time() > deadline:
                self.logger.info(self.vapi.cli("show sr policies"))
                self.fail(
                    "path MTU of %s is %s, expected %s"
                    % (first_segment, found, expected)
                )
            self.sleep(0.1)

    def err_counter(self, node, name):
        return self.statistics.get_err_counter("/err/%s/%s" % (node, name))

    def inner_of(self, rx, segments):
        """The inner packet of an encapsulated packet"""
        if len(segments) > 1:
            return rx[IPv6ExtHdrSegmentRouting].payload
        return rx[IPv6].payload

    def verify_encapsulated(self, rx, tx, segments, mtu):
        """rx is tx encapsulated with the segment list and fits the MTU"""
        outer = rx[IPv6]
        self.assertEqual(outer.src, ENCAP_SRC)
        self.assertEqual(outer.dst, segments[0])
        self.assertLessEqual(len(outer), mtu)
        if len(segments) > 1:
            self.assertEqual(
                rx[IPv6ExtHdrSegmentRouting].addresses, list(reversed(segments))
            )
        if IPv6 in tx:
            expected = tx[IPv6].copy()
            expected.hlim -= 1
        else:
            expected = tx[IP].copy()
            expected.ttl -= 1
            del expected.chksum
        self.assertEqual(bytes(self.inner_of(rx, segments)), bytes(expected))

    def verify_packet_too_big(self, rx, intf, tx, mtu):
        """rx is the ICMPv6 Packet Too Big for tx, sent back to intf"""
        self.assertEqual(rx[IPv6].src, intf.local_ip6)
        self.assertEqual(rx[IPv6].dst, intf.remote_ip6)
        self.assertEqual(rx[ICMPv6PacketTooBig].mtu, mtu)
        self.assertEqual(rx[IPerror6].src, tx[IPv6].src)
        self.assertEqual(rx[IPerror6].dst, tx[IPv6].dst)

    def verify_frag_needed(self, rx, intf, tx, mtu):
        """rx is the ICMPv4 fragmentation needed for tx, sent back to intf"""
        self.assertEqual(rx[IP].src, intf.local_ip4)
        self.assertEqual(rx[IP].dst, intf.remote_ip4)
        # destination unreachable, fragmentation needed and DF set
        self.assertEqual(rx[ICMP].type, 3)
        self.assertEqual(rx[ICMP].code, 4)
        self.assertEqual(rx[ICMP].nexthopmtu, mtu)
        self.assertEqual(rx[IPerror].src, tx[IP].src)
        self.assertEqual(rx[IPerror].dst, tx[IP].dst)

    def verify_fragments(self, rxs, tx, mtu, inner_mtu):
        """rxs are encapsulated fragments of tx that fit the MTUs"""
        frags = []
        for rx in rxs:
            self.assertEqual(rx[IPv6].src, ENCAP_SRC)
            self.assertEqual(rx[IPv6].dst, SEGMENT)
            self.assertLessEqual(len(rx[IPv6]), mtu)
            frag = rx[IP]
            self.assertLessEqual(len(frag), inner_mtu)
            frags.append(frag)
        frags.sort(key=lambda p: p.frag)
        self.assertEqual(frags[0].frag, 0)
        reassembled = reassemble4(frags)
        self.assertEqual(reassembled.src, tx[IP].src)
        self.assertEqual(reassembled.dst, tx[IP].dst)
        self.assertEqual(reassembled.ttl, tx[IP].ttl - 1)
        self.assertEqual(bytes(reassembled[IP].payload), bytes(tx[IP].payload))

    def n_fragments(self, length, inner_mtu):
        """Number of IPv4 fragments for a packet of the length"""
        data = length - 20
        per_fragment = (inner_mtu - 20) & ~7
        return -(-data // per_fragment)

    def test_ipv6_too_big(self):
        """IPv6 packet too big after encaps gets ICMPv6 Packet Too Big"""
        self.pg1.set_ip6_mtu(EGRESS_MTU)
        self.add_policy([SEGMENT])
        self.steer()

        tx = self.ip6_packet(self.pg0, INNER_MTU + 1)
        rx = self.send_and_expect(
            self.pg0, tx, self.pg0, assert_nothing_captured=self.pg_interfaces
        )
        self.verify_packet_too_big(rx[0], self.pg0, tx, INNER_MTU)

    def test_ipv4_too_big_with_df(self):
        """IPv4 packet with DF too big after encaps gets ICMPv4 frag needed"""
        self.pg1.set_ip6_mtu(EGRESS_MTU)
        self.add_policy([SEGMENT])
        self.steer()

        tx = self.ip4_packet(self.pg0, INNER_MTU + 1, df=True)
        rx = self.send_and_expect(
            self.pg0, tx, self.pg0, assert_nothing_captured=self.pg_interfaces
        )
        self.verify_frag_needed(rx[0], self.pg0, tx, INNER_MTU)

    def test_ipv4_too_big_without_df(self):
        """IPv4 packet without DF too big after encaps is fragmented first"""
        self.pg1.set_ip6_mtu(EGRESS_MTU)
        self.add_policy([SEGMENT])
        self.steer()

        # larger than a buffer, so the packet is a buffer chain
        length = 3028
        tx = self.ip4_packet(self.pg0, length, df=False)
        rx = self.send_and_expect(
            self.pg0,
            tx,
            self.pg1,
            n_rx=self.n_fragments(length, INNER_MTU),
            assert_nothing_captured=self.pg_interfaces,
        )
        self.verify_fragments(rx, tx, EGRESS_MTU, INNER_MTU)

    def test_packets_at_the_limit(self):
        """Packets that fit exactly after encaps are encapsulated"""
        self.pg1.set_ip6_mtu(EGRESS_MTU)
        self.add_policy([SEGMENT])
        self.steer()

        for tx in (
            self.ip6_packet(self.pg0, INNER_MTU),
            self.ip4_packet(self.pg0, INNER_MTU, df=True),
            self.ip4_packet(self.pg0, INNER_MTU, df=False),
        ):
            rx = self.send_and_expect(
                self.pg0, tx, self.pg1, assert_nothing_captured=self.pg_interfaces
            )
            self.verify_encapsulated(rx[0], tx, [SEGMENT], EGRESS_MTU)
            self.assertEqual(len(rx[0][IPv6]), EGRESS_MTU)

    def test_srh_in_encap_length(self):
        """The SRH counts in the encap length"""
        segments = [SEGMENT, SRH_SEGMENT]
        inner_mtu = EGRESS_MTU - IP6_HDR_LEN - SRH_2_SEGMENTS_LEN
        self.pg1.set_ip6_mtu(EGRESS_MTU)
        self.add_policy(segments)
        self.steer()

        tx = self.ip6_packet(self.pg0, inner_mtu)
        rx = self.send_and_expect(
            self.pg0, tx, self.pg1, assert_nothing_captured=self.pg_interfaces
        )
        self.verify_encapsulated(rx[0], tx, segments, EGRESS_MTU)
        self.assertEqual(len(rx[0][IPv6]), EGRESS_MTU)

        tx = self.ip6_packet(self.pg0, inner_mtu + 1)
        rx = self.send_and_expect(
            self.pg0, tx, self.pg0, assert_nothing_captured=self.pg_interfaces
        )
        self.verify_packet_too_big(rx[0], self.pg0, tx, inner_mtu)

        tx = self.ip4_packet(self.pg0, inner_mtu + 1, df=True)
        rx = self.send_and_expect(
            self.pg0, tx, self.pg0, assert_nothing_captured=self.pg_interfaces
        )
        self.verify_frag_needed(rx[0], self.pg0, tx, inner_mtu)

    def test_limit_follows_changes(self):
        """The limit follows interface MTU and route changes"""
        self.add_policy([SEGMENT])
        self.steer()
        self.wait_for_path_mtu(SEGMENT, DEFAULT_MTU)

        tx = self.ip6_packet(self.pg0, INNER_MTU + 1)
        rx = self.send_and_expect(
            self.pg0, tx, self.pg1, assert_nothing_captured=self.pg_interfaces
        )
        self.verify_encapsulated(rx[0], tx, [SEGMENT], DEFAULT_MTU)

        # smaller MTU on the egress interface
        self.pg1.set_ip6_mtu(EGRESS_MTU)
        self.wait_for_path_mtu(SEGMENT, EGRESS_MTU)
        rx = self.send_and_expect(
            self.pg0, tx, self.pg0, assert_nothing_captured=self.pg_interfaces
        )
        self.verify_packet_too_big(rx[0], self.pg0, tx, INNER_MTU)

        # the route to the first segment moves to an interface with an
        # even smaller MTU
        self.pg2.set_ip6_mtu(OTHER_MTU)
        self.route.modify([VppRoutePath(self.pg2.remote_ip6, self.pg2.sw_if_index)])
        self.wait_for_path_mtu(SEGMENT, OTHER_MTU)
        other_inner_mtu = OTHER_MTU - IP6_HDR_LEN
        tx = self.ip6_packet(self.pg0, other_inner_mtu + 1)
        rx = self.send_and_expect(
            self.pg0, tx, self.pg0, assert_nothing_captured=self.pg_interfaces
        )
        self.verify_packet_too_big(rx[0], self.pg0, tx, other_inner_mtu)
        tx = self.ip6_packet(self.pg0, other_inner_mtu)
        rx = self.send_and_expect(
            self.pg0, tx, self.pg2, assert_nothing_captured=self.pg_interfaces
        )
        self.verify_encapsulated(rx[0], tx, [SEGMENT], OTHER_MTU)

        # a larger MTU lets bigger packets through again
        self.pg2.set_ip6_mtu(DEFAULT_MTU)
        self.wait_for_path_mtu(SEGMENT, DEFAULT_MTU)
        tx = self.ip6_packet(self.pg0, INNER_MTU + 1)
        rx = self.send_and_expect(
            self.pg0, tx, self.pg2, assert_nothing_captured=self.pg_interfaces
        )
        self.verify_encapsulated(rx[0], tx, [SEGMENT], DEFAULT_MTU)

        # no route to the first segment, so no MTU is known
        self.route.remove_vpp_config()
        self.wait_for_path_mtu(SEGMENT, None)

    def test_icmp_to_ingress_vrf(self):
        """ICMP errors go back into the VRF of the ingress interface"""
        self.pg1.set_ip6_mtu(EGRESS_MTU)
        self.add_policy([SEGMENT])
        self.steer(table_id=VRF)

        tx = self.ip6_packet(self.pg3, INNER_MTU + 1)
        rx = self.send_and_expect(
            self.pg3, tx, self.pg3, assert_nothing_captured=self.pg_interfaces
        )
        self.verify_packet_too_big(rx[0], self.pg3, tx, INNER_MTU)

        tx = self.ip4_packet(self.pg3, INNER_MTU + 1, df=True)
        rx = self.send_and_expect(
            self.pg3, tx, self.pg3, assert_nothing_captured=self.pg_interfaces
        )
        self.verify_frag_needed(rx[0], self.pg3, tx, INNER_MTU)

        tx = self.ip6_packet(self.pg3, INNER_MTU)
        rx = self.send_and_expect(
            self.pg3, tx, self.pg1, assert_nothing_captured=self.pg_interfaces
        )
        self.verify_encapsulated(rx[0], tx, [SEGMENT], EGRESS_MTU)

        length = 3028
        tx = self.ip4_packet(self.pg3, length, df=False)
        rx = self.send_and_expect(
            self.pg3,
            tx,
            self.pg1,
            n_rx=self.n_fragments(length, INNER_MTU),
            assert_nothing_captured=self.pg_interfaces,
        )
        self.verify_fragments(rx, tx, EGRESS_MTU, INNER_MTU)

    def test_multipath_smallest_mtu(self):
        """With several paths to the first segment the smallest MTU is used"""
        self.pg1.set_ip6_mtu(EGRESS_MTU)
        self.pg2.set_ip6_mtu(OTHER_MTU)
        self.add_policy([SEGMENT])
        self.steer()
        self.wait_for_path_mtu(SEGMENT, EGRESS_MTU)

        self.route.modify(
            [
                VppRoutePath(self.pg1.remote_ip6, self.pg1.sw_if_index),
                VppRoutePath(self.pg2.remote_ip6, self.pg2.sw_if_index),
            ]
        )
        self.wait_for_path_mtu(SEGMENT, OTHER_MTU)

        inner_mtu = OTHER_MTU - IP6_HDR_LEN
        tx = self.ip6_packet(self.pg0, inner_mtu + 1)
        rx = self.send_and_expect(
            self.pg0, tx, self.pg0, assert_nothing_captured=self.pg_interfaces
        )
        self.verify_packet_too_big(rx[0], self.pg0, tx, inner_mtu)

    def test_removed_segment_lists_stop_tracking(self):
        """Removed segment lists stop tracking their first segment"""
        policy = self.add_policy([SEGMENT], [OTHER_SEGMENT])
        self.assertTrue(find_route(self, SEGMENT, 128))
        self.assertTrue(find_route(self, OTHER_SEGMENT, 128))
        self.wait_for_path_mtu(SEGMENT, DEFAULT_MTU)
        self.wait_for_path_mtu(OTHER_SEGMENT, DEFAULT_MTU)

        sl_index = None
        for p in self.vapi.sr_policies_with_sl_index_dump():
            for sl in p.sid_lists[: p.num_sid_lists]:
                if str(sl.sids[0]) == OTHER_SEGMENT:
                    sl_index = sl.sl_index
        self.vapi.cli("sr policy mod bsid %s del sl index %d" % (BSID, sl_index))
        self.assertIsNone(self.path_mtu(OTHER_SEGMENT))
        self.assertFalse(find_route(self, OTHER_SEGMENT, 128))

        # the walk after an MTU change still reaches the list that is left
        self.pg2.set_ip6_mtu(OTHER_MTU)
        self.pg1.set_ip6_mtu(EGRESS_MTU)
        self.wait_for_path_mtu(SEGMENT, EGRESS_MTU)

        policy.remove_vpp_config()
        self.sr_objects.remove(policy)
        self.assertFalse(find_route(self, SEGMENT, 128))

    def test_burst(self):
        """Bursts mix packets that fit, too big and fragmented packets"""
        self.pg1.set_ip6_mtu(EGRESS_MTU)
        self.add_policy([SEGMENT])
        self.steer()
        too_big6 = self.err_counter(ENCAPS6_NODE, TOO_BIG)
        too_big4 = self.err_counter(ENCAPS4_NODE, TOO_BIG)
        fragmented4 = self.err_counter(ENCAPS4_NODE, FRAGMENTED)

        # Groups of four go through the quad loop, except the last group.
        # "f" fits, "b" is too big, "d" is too big with DF.
        pattern = "ffff" + "fbfb" + "ffff" + "bffb"
        fit = INNER_MTU
        big = INNER_MTU + 1

        txs = [
            self.ip6_packet(self.pg0, fit if c == "f" else big, sport=1000 + n)
            for n, c in enumerate(pattern)
        ]
        rxs = self.send_and_expect(self.pg0, txs, self.pg1, n_rx=pattern.count("f"))
        by_sport = {rx[UDP].sport: rx for rx in rxs}
        for n, c in enumerate(pattern):
            if c == "f":
                self.verify_encapsulated(
                    by_sport[1000 + n], txs[n], [SEGMENT], EGRESS_MTU
                )
        self.assertEqual(
            self.err_counter(ENCAPS6_NODE, TOO_BIG) - too_big6, pattern.count("b")
        )

        pattern = "ffff" + "fdfb" + "ffff" + "bffd"
        # a 1500 byte packet makes two fragments
        big = 1500
        txs = [
            self.ip4_packet(self.pg0, fit if c == "f" else big, df=c == "d", ip_id=n)
            for n, c in enumerate(pattern)
        ]
        n_rx = pattern.count("f") + 2 * pattern.count("b")
        rxs = self.send_and_expect(self.pg0, txs, self.pg1, n_rx=n_rx)
        # fragments get a new IP id, so they are grouped by that id
        whole = {}
        fragments = {}
        for rx in rxs:
            inner = rx[IP]
            if inner.frag == 0 and not inner.flags.MF:
                whole[inner.id] = rx
            else:
                fragments.setdefault(inner.id, []).append(rx)
        for n, c in enumerate(pattern):
            if c == "f":
                self.verify_encapsulated(whole[n], txs[n], [SEGMENT], EGRESS_MTU)
        self.assertEqual(len(fragments), pattern.count("b"))
        # all the packets that are too big have the same content
        big_tx = txs[pattern.index("b")]
        for frags in fragments.values():
            self.verify_fragments(frags, big_tx, EGRESS_MTU, INNER_MTU)
        self.assertEqual(
            self.err_counter(ENCAPS4_NODE, TOO_BIG) - too_big4, pattern.count("d")
        )
        self.assertEqual(
            self.err_counter(ENCAPS4_NODE, FRAGMENTED) - fragmented4,
            pattern.count("b"),
        )


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
