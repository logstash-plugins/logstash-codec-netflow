#!/usr/bin/env python2
import socket
import sys
import time


# IPFIX template
tpl = "000a00585b6b5242000010bda07e8c0000020048010000100001000400020004000400010008000400070002000a0004000b0002000c0004000e0004000f0004001500040016000400e1000400e2000400e3000200e40002".decode("hex")
'''
Cisco NetFlow/IPFIX
    Version: 10
    Length: 88
    Timestamp: Aug  8, 2018 14:27:46.000000000 MDT
        ExportTime: 1533760066
    FlowSequence: 4285
    Observation Domain Id: 2692647936
    Set 1 [id=2] (Data Template): 256
        FlowSet Id: Data Template (V10 [IPFIX]) (2)
        FlowSet Length: 72
        Template (Id = 256, Count = 16)
            Template Id: 256
            Field Count: 16
            Field (1/16): BYTES
                0... .... .... .... = Pen provided: No
                .000 0000 0000 0001 = Type: BYTES (1)
                Length: 4
            Field (2/16): PKTS
                0... .... .... .... = Pen provided: No
                .000 0000 0000 0010 = Type: PKTS (2)
                Length: 4
            Field (3/16): PROTOCOL
                0... .... .... .... = Pen provided: No
                .000 0000 0000 0100 = Type: PROTOCOL (4)
                Length: 1
            Field (4/16): IP_SRC_ADDR
                0... .... .... .... = Pen provided: No
                .000 0000 0000 1000 = Type: IP_SRC_ADDR (8)
                Length: 4
            Field (5/16): L4_SRC_PORT
                0... .... .... .... = Pen provided: No
                .000 0000 0000 0111 = Type: L4_SRC_PORT (7)
                Length: 2
            Field (6/16): INPUT_SNMP
                0... .... .... .... = Pen provided: No
                .000 0000 0000 1010 = Type: INPUT_SNMP (10)
                Length: 4
            Field (7/16): L4_DST_PORT
                0... .... .... .... = Pen provided: No
                .000 0000 0000 1011 = Type: L4_DST_PORT (11)
                Length: 2
            Field (8/16): IP_DST_ADDR
                0... .... .... .... = Pen provided: No
                .000 0000 0000 1100 = Type: IP_DST_ADDR (12)
                Length: 4
            Field (9/16): OUTPUT_SNMP
                0... .... .... .... = Pen provided: No
                .000 0000 0000 1110 = Type: OUTPUT_SNMP (14)
                Length: 4
            Field (10/16): IP_NEXT_HOP
                0... .... .... .... = Pen provided: No
                .000 0000 0000 1111 = Type: IP_NEXT_HOP (15)
                Length: 4
            Field (11/16): LAST_SWITCHED
                0... .... .... .... = Pen provided: No
                .000 0000 0001 0101 = Type: LAST_SWITCHED (21)
                Length: 4
            Field (12/16): FIRST_SWITCHED
                0... .... .... .... = Pen provided: No
                .000 0000 0001 0110 = Type: FIRST_SWITCHED (22)
                Length: 4
            Field (13/16): postNATSourceIPv4Address
                0... .... .... .... = Pen provided: No
                .000 0000 1110 0001 = Type: postNATSourceIPv4Address (225)
                Length: 4
            Field (14/16): postNATDestinationIPv4Address
                0... .... .... .... = Pen provided: No
                .000 0000 1110 0010 = Type: postNATDestinationIPv4Address (226)
                Length: 4
            Field (15/16): postNAPTSourceTransportPort
                0... .... .... .... = Pen provided: No
                .000 0000 1110 0011 = Type: postNAPTSourceTransportPort (227)
                Length: 2
            Field (16/16): postNAPTDestinationTransportPort
                0... .... .... .... = Pen provided: No
                .000 0000 1110 0100 = Type: postNAPTDestinationTransportPort (228)
                Length: 2
'''

data = "000a011d5b6b86c50000acf0a07e8c000100010d0010d49a000002fa06acd9022501bb00000002a3290a0000ed000000010a00000100dedac800debb88acd90225c0a8a84101bbdd690000009d00000001114b4b4b4b003500000002222c0a0000ed000000010a00000100de715000de71504b4b4b4bc0a8a8410035398f0000024600000005114a7d8a7101bb00000002d3d10a0000ed000000010a00000100de715000de71504a7d8a71c0a8a84101bb9ca40000038300000004114a7d8a7101bb0000000268920a0000ed000000010a00000100de715000de71504a7d8a71c0a8a84101bba46b000001c6000000040623a8ede501bb000000023d1b0a0000ed000000010a00000100de753800023a5023a8ede5c0a8a84101bbeb10".decode("hex")

'''
Cisco NetFlow/IPFIX
    Version: 10
    Length: 285
    Timestamp: Aug  8, 2018 18:11:49.000000000 MDT
        ExportTime: 1533773509
    FlowSequence: 44272
    Observation Domain Id: 2692647936
    Set 1 [id=256] (5 flows)
        FlowSet Id: (Data) (256)
        FlowSet Length: 269
        [Template Frame: 54]
        Flow 1
            Octets: 1103002
            Packets: 762
            Protocol: TCP (6)
            SrcAddr: 172.217.2.37
            SrcPort: 443 (443)
            InputInt: 2
            DstPort: 41769 (41769)
            DstAddr: 10.0.0.237
            OutputInt: 1
            NextHop: 10.0.0.1
            [Duration: 8.000000000 seconds (switched)]
                StartTime: 14597.000000000 seconds
                EndTime: 14605.000000000 seconds
            Post NAT Source IPv4 Address: 172.217.2.37
            Post NAT Destination IPv4 Address: 192.168.168.65
            Post NAPT Source Transport Port: 443
            Post NAPT Destination Transport Port: 56681
        Flow 2
            Octets: 157
            Packets: 1
            Protocol: UDP (17)
            SrcAddr: 75.75.75.75
            SrcPort: 53 (53)
            InputInt: 2
            DstPort: 8748 (8748)
            DstAddr: 10.0.0.237
            OutputInt: 1
            NextHop: 10.0.0.1
            [Duration: 0.000000000 seconds (switched)]
                StartTime: 14578.000000000 seconds
                EndTime: 14578.000000000 seconds
            Post NAT Source IPv4 Address: 75.75.75.75
            Post NAT Destination IPv4 Address: 192.168.168.65
            Post NAPT Source Transport Port: 53
            Post NAPT Destination Transport Port: 14735
        Flow 3
            Octets: 582
            Packets: 5
            Protocol: UDP (17)
            SrcAddr: 74.125.138.113
            SrcPort: 443 (443)
            InputInt: 2
            DstPort: 54225 (54225)
            DstAddr: 10.0.0.237
            OutputInt: 1
            NextHop: 10.0.0.1
            [Duration: 0.000000000 seconds (switched)]
                StartTime: 14578.000000000 seconds
                EndTime: 14578.000000000 seconds
            Post NAT Source IPv4 Address: 74.125.138.113
            Post NAT Destination IPv4 Address: 192.168.168.65
            Post NAPT Source Transport Port: 443
            Post NAPT Destination Transport Port: 40100
        Flow 4
            Octets: 899
            Packets: 4
            Protocol: UDP (17)
            SrcAddr: 74.125.138.113
            SrcPort: 443 (443)
            InputInt: 2
            DstPort: 26770 (26770)
            DstAddr: 10.0.0.237
            OutputInt: 1
            NextHop: 10.0.0.1
            [Duration: 0.000000000 seconds (switched)]
                StartTime: 14578.000000000 seconds
                EndTime: 14578.000000000 seconds
            Post NAT Source IPv4 Address: 74.125.138.113
            Post NAT Destination IPv4 Address: 192.168.168.65
            Post NAPT Source Transport Port: 443
            Post NAPT Destination Transport Port: 42091
        Flow 5
            Octets: 454
            Packets: 4
            Protocol: TCP (6)
            SrcAddr: 35.168.237.229
            SrcPort: 443 (443)
            InputInt: 2
            DstPort: 15643 (15643)
            DstAddr: 10.0.0.237
            OutputInt: 1
            NextHop: 10.0.0.1
            [Duration: 14433.000000000 seconds (switched)]
                StartTime: 146.000000000 seconds
                EndTime: 14579.000000000 seconds
            Post NAT Source IPv4 Address: 35.168.237.229
            Post NAT Destination IPv4 Address: 192.168.168.65
            Post NAPT Source Transport Port: 443
            Post NAPT Destination Transport Port: 60176
'''

host = sys.argv[1]
port = 2055
N = 150000
flowsPerPacket = 5

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(tpl, (host, port))
time.sleep(0.2)

ts = time.time()
print("%d: started sending %d SonicWALL IPFIX flows in %d packets totaling %d bytes" % (ts,N*flowsPerPacket, N, N*len(data)))
print("%d: flow size %d, packet size %d" % (ts, len(data) / flowsPerPacket, len(data)))

for i in range(0, N):
    sock.sendto(data, (host, port))
