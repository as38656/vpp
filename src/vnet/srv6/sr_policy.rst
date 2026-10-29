.. _srv6_policy_doc:

Creating a SR Policy
====================

An SR Policy is defined by a Binding SID and a weighted set of Segment
Lists.

A new SR policy is created with a first SID list using:

::

   sr policy add bsid 2001::1 next A1:: next B1:: next C1:: (weight 5) (fib-table 3)

-  The weight parameter is only used if more than one SID list is
   associated with the policy.
-  The fib-table parameter specifies in which table (VRF) the Binding
   SID is to be installed.

An SR policy is deleted with:

::

   sr policy del bsid 2001::1
   sr policy del index 1

The existing SR policies are listed with:

::

   show sr policies

Adding/Removing SID Lists from an SR policy
-------------------------------------------

An additional SID list is associated with an existing SR policy with:

::

   sr policy mod bsid 2001::1 add sl next A2:: next B2:: next C2:: (weight 3)
   sr policy mod index 3      add sl next A2:: next B2:: next C2:: (weight 3)

Conversely, a SID list can be removed from an SR policy with:

::

   sr policy mod bsid 2001::1 del sl index 1
   sr policy mod index 3      del sl index 1

Note that this cannot be used to remove the last SID list of a policy.

The weight of a SID list can also be modified with:

::

   sr policy mod bsid 2001::1 mod sl index 1 weight 4
   sr policy mod index 3      mod sl index 1 weight 4

SR Policies: Spray policies
---------------------------

Spray policies are a specific type of SR policies where the packet is
replicated on all the SID lists, rather than load-balanced among them.

SID list weights are ignored with this type of policies.

A Spray policy is instantiated by appending the keyword **spray** to a
regular SR policy command, as in:

::

   sr policy add bsid 2001::1 next A1:: next B1:: next C1:: spray

Spray policies are used for removing multicast state from a network core
domain, and instead send a linear unicast copy to every access node. The
last SID in each list accesses the multicast tree within the access
node.

Encapsulation SR policies
-------------------------

In case the user decides to create an SR policy an IPv6 Source Address
must be specified for the encapsulated traffic. In order to do so the
user might use the following command:

::

   set sr encaps source addr XXXX::YYYY

Default hop-limit for the encapsulating IPv6 header is 64. It is
possible to specify custom hop-limit value from 1 to 255 using this
command:

::

   set sr encaps hop-limit N

Path MTU of encapsulation policies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each segment list follows the MTU of the path to its first segment in
the egress table: the smallest IPv6 MTU of the interfaces that the route
to the first segment uses. The value changes when the route or the MTU
of such an interface changes. The inner MTU is the path MTU minus the
length of the encapsulation (the IPv6 header, and the SRH when there is
one).

Before encapsulation, the headend checks IPv6 and IPv4 packets against
the inner MTU. A packet that is larger is handled like this:

-  IPv6: the packet is dropped, and an ICMPv6 Packet Too Big with the
   inner MTU is sent to its source.
-  IPv4 with DF: the packet is dropped, and an ICMPv4 Fragmentation
   Needed with the inner MTU is sent to its source.
-  IPv4 without DF: the packet is fragmented to the inner MTU, then
   each fragment is encapsulated.

The ICMP errors are sent from an address of the interface that received
the packet, and are routed in the table of that interface. There is no
check when the path MTU is not known (for example when the first segment
is not reachable) or when it is less than 1280.

The path MTU and the inner MTU of each segment list are shown by:

::

   show sr policies

SRH insertion, L2 encapsulation and packets with the Binding SID as
destination are not checked.
