from scapy.all import Ether, IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, sendp


p = (Ether()/IPv6(src="fe80:5ebe:2294:ecd0:5eee:1aff:fec9:f7f7")/
     ICMPv6ND_RA(routerlifetime=10)/
     ICMPv6NDOptPrefixInfo(prefix="3001:5ebe:2294:ecd0::", prefixlen=64,
                          validlifetime=10,preferredlifetime=10))

sendp(p, iface="r1-eth1")