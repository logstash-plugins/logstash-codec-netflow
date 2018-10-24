#!/usr/bin/env python2
import socket
import sys
import time


# IPFIX template
tpl = "000a03605b6cb59300008a310000000000020228c013000600b80004800e000100001ad7800f000100001ad7c00e000100001ad7c00f000100001ad780b8000400007279c015001781f6000800001ad781f7000800001ad781f8000800001ad700df000481f4000400001ad781f5000400001ad781fe000400001ad781f9000200001ad781fa000200001ad781fc000200001ad781fb000100001ad700d20001c1f6000800001ad7c1f7000800001ad7c1f8000800001ad780df000400007279c1f4000400001ad7c1f5000400001ad7c1fe000400001ad7c1f9000200001ad7c1fa000200001ad7c1fc000200001ad700d20002b301000e0098000800990008005500040056000400080004000c000400070002000b00028028000200001ad70004000100880001003a0002000500010125ffffc01800028012ffff00001ad7c012ffff00001ad7b80000270098000800990008005500088055000800007279005600088056000800007279000100088001000800007279000200088002000800007279001b0010001c001000080004000c000400070002000b00028028000200001ad7c028000200001ad7000400010088000100d200028015000400001ad700b8000480b8000400007279800e000100001ad7800f000100001ad7c00e000100001ad7c00f000100001ad7003a0002803a000200007279000a0004000e000400050001800500010000727900460003004700030048000300d200050125ffffc003000300b80004800e000100001ad7800f000100001ad70003007cd000000e000200a00008002a0008005600080087000800a4000800a700088064000400001ad78065000400001ad78068000400001ad78069000400001ad700820004009000048066000400001ad78067000400001ad7d001000400028227000200001ad78228000200001ad78226000400001ad70124ffff000200acd00200020090000401420004c00400020038000600500006c005000b81f6000800001ad781f7000800001ad781f8000800001ad700df000481f4000400001ad781f5000400001ad781fe000400001ad781f9000200001ad781fa000200001ad781fc000200001ad781fb000100001ad7c00900058121000800001ad78122000400001ad78123000200001ad78124000100001ad78125000100001ad7c00800018012ffff00001ad7".decode("hex")

'''
Cisco NetFlow/IPFIX
    Version: 10
    Length: 864
    Timestamp: Aug  9, 2018 15:43:47.000000000 MDT
        ExportTime: 1533851027
    FlowSequence: 35377
    Observation Domain Id: 0
    Set 1 [id=2] (Data Template): 49171,49173,45825,49176,47104,49155
        FlowSet Id: Data Template (V10 [IPFIX]) (2)
        FlowSet Length: 552
        Template (Id = 49171, Count = 6)
            Template Id: 49171
            Field Count: 6
            Field (1/6): TCP_SEQ_NUM
                0... .... .... .... = Pen provided: No
                .000 0000 1011 1000 = Type: TCP_SEQ_NUM (184)
                Length: 4
            Field (2/6):  14 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0000 1110 = Type: 14 [pen: CERT Coordination Center]
                Length: 1
                PEN: CERT Coordination Center (6871)
            Field (3/6):  15 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0000 1111 = Type: 15 [pen: CERT Coordination Center]
                Length: 1
                PEN: CERT Coordination Center (6871)
            Field (4/6): 16398 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .100 0000 0000 1110 = Type: 16398 [pen: CERT Coordination Center]
                Length: 1
                PEN: CERT Coordination Center (6871)
            Field (5/6): 16399 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .100 0000 0000 1111 = Type: 16399 [pen: CERT Coordination Center]
                Length: 1
                PEN: CERT Coordination Center (6871)
            Field (6/6): TCP_SEQ_NUM [Reverse]
                1... .... .... .... = Pen provided: Yes
                .000 0000 1011 1000 = Type: TCP_SEQ_NUM (184) [Reverse]
                Length: 4
                PEN: IPFIX Reverse Information Element Private Enterprise (29305)
        Template (Id = 49173, Count = 23)
            Template Id: 49173
            Field Count: 23
            Field (1/23): 502 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 0110 = Type: 502 [pen: CERT Coordination Center]
                Length: 8
                PEN: CERT Coordination Center (6871)
            Field (2/23): 503 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 0111 = Type: 503 [pen: CERT Coordination Center]
                Length: 8
                PEN: CERT Coordination Center (6871)
            Field (3/23): 504 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 1000 = Type: 504 [pen: CERT Coordination Center]
                Length: 8
                PEN: CERT Coordination Center (6871)
            Field (4/23): tcpUrgTotalCount
                0... .... .... .... = Pen provided: No
                .000 0000 1101 1111 = Type: tcpUrgTotalCount (223)
                Length: 4
            Field (5/23): 500 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 0100 = Type: 500 [pen: CERT Coordination Center]
                Length: 4
                PEN: CERT Coordination Center (6871)
            Field (6/23): 501 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 0101 = Type: 501 [pen: CERT Coordination Center]
                Length: 4
                PEN: CERT Coordination Center (6871)
            Field (7/23): 510 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 1110 = Type: 510 [pen: CERT Coordination Center]
                Length: 4
                PEN: CERT Coordination Center (6871)
            Field (8/23): 505 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 1001 = Type: 505 [pen: CERT Coordination Center]
                Length: 2
                PEN: CERT Coordination Center (6871)
            Field (9/23): 506 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 1010 = Type: 506 [pen: CERT Coordination Center]
                Length: 2
                PEN: CERT Coordination Center (6871)
            Field (10/23): 508 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 1100 = Type: 508 [pen: CERT Coordination Center]
                Length: 2
                PEN: CERT Coordination Center (6871)
            Field (11/23): 507 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 1011 = Type: 507 [pen: CERT Coordination Center]
                Length: 1
                PEN: CERT Coordination Center (6871)
            Field (12/23): paddingOctets
                0... .... .... .... = Pen provided: No
                .000 0000 1101 0010 = Type: paddingOctets (210)
                Length: 1
            Field (13/23): 16886 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .100 0001 1111 0110 = Type: 16886 [pen: CERT Coordination Center]
                Length: 8
                PEN: CERT Coordination Center (6871)
            Field (14/23): 16887 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .100 0001 1111 0111 = Type: 16887 [pen: CERT Coordination Center]
                Length: 8
                PEN: CERT Coordination Center (6871)
            Field (15/23): 16888 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .100 0001 1111 1000 = Type: 16888 [pen: CERT Coordination Center]
                Length: 8
                PEN: CERT Coordination Center (6871)
            Field (16/23): tcpUrgTotalCount [Reverse]
                1... .... .... .... = Pen provided: Yes
                .000 0000 1101 1111 = Type: tcpUrgTotalCount (223) [Reverse]
                Length: 4
                PEN: IPFIX Reverse Information Element Private Enterprise (29305)
            Field (17/23): 16884 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .100 0001 1111 0100 = Type: 16884 [pen: CERT Coordination Center]
                Length: 4
                PEN: CERT Coordination Center (6871)
            Field (18/23): 16885 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .100 0001 1111 0101 = Type: 16885 [pen: CERT Coordination Center]
                Length: 4
                PEN: CERT Coordination Center (6871)
            Field (19/23): 16894 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .100 0001 1111 1110 = Type: 16894 [pen: CERT Coordination Center]
                Length: 4
                PEN: CERT Coordination Center (6871)
            Field (20/23): 16889 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .100 0001 1111 1001 = Type: 16889 [pen: CERT Coordination Center]
                Length: 2
                PEN: CERT Coordination Center (6871)
            Field (21/23): 16890 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .100 0001 1111 1010 = Type: 16890 [pen: CERT Coordination Center]
                Length: 2
                PEN: CERT Coordination Center (6871)
            Field (22/23): 16892 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .100 0001 1111 1100 = Type: 16892 [pen: CERT Coordination Center]
                Length: 2
                PEN: CERT Coordination Center (6871)
            Field (23/23): paddingOctets
                0... .... .... .... = Pen provided: No
                .000 0000 1101 0010 = Type: paddingOctets (210)
                Length: 2
        Template (Id = 45825, Count = 14)
            Template Id: 45825
            Field Count: 14
            Field (1/14): flowStartMilliseconds
                0... .... .... .... = Pen provided: No
                .000 0000 1001 1000 = Type: flowStartMilliseconds (152)
                Length: 8
            Field (2/14): flowEndMilliseconds
                0... .... .... .... = Pen provided: No
                .000 0000 1001 1001 = Type: flowEndMilliseconds (153)
                Length: 8
            Field (3/14): BYTES_TOTAL
                0... .... .... .... = Pen provided: No
                .000 0000 0101 0101 = Type: BYTES_TOTAL (85)
                Length: 4
            Field (4/14): PACKETS_TOTAL
                0... .... .... .... = Pen provided: No
                .000 0000 0101 0110 = Type: PACKETS_TOTAL (86)
                Length: 4
            Field (5/14): IP_SRC_ADDR
                0... .... .... .... = Pen provided: No
                .000 0000 0000 1000 = Type: IP_SRC_ADDR (8)
                Length: 4
            Field (6/14): IP_DST_ADDR
                0... .... .... .... = Pen provided: No
                .000 0000 0000 1100 = Type: IP_DST_ADDR (12)
                Length: 4
            Field (7/14): L4_SRC_PORT
                0... .... .... .... = Pen provided: No
                .000 0000 0000 0111 = Type: L4_SRC_PORT (7)
                Length: 2
            Field (8/14): L4_DST_PORT
                0... .... .... .... = Pen provided: No
                .000 0000 0000 1011 = Type: L4_DST_PORT (11)
                Length: 2
            Field (9/14):  40 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0010 1000 = Type: 40 [pen: CERT Coordination Center]
                Length: 2
                PEN: CERT Coordination Center (6871)
            Field (10/14): PROTOCOL
                0... .... .... .... = Pen provided: No
                .000 0000 0000 0100 = Type: PROTOCOL (4)
                Length: 1
            Field (11/14): flowEndReason
                0... .... .... .... = Pen provided: No
                .000 0000 1000 1000 = Type: flowEndReason (136)
                Length: 1
            Field (12/14): SRC_VLAN
                0... .... .... .... = Pen provided: No
                .000 0000 0011 1010 = Type: SRC_VLAN (58)
                Length: 2
            Field (13/14): IP_TOS
                0... .... .... .... = Pen provided: No
                .000 0000 0000 0101 = Type: IP_TOS (5)
                Length: 1
            Field (14/14): subTemplateMultiList
                0... .... .... .... = Pen provided: No
                .000 0001 0010 0101 = Type: subTemplateMultiList (293)
                Length: 65535 [i.e.: "Variable Length"]
        Template (Id = 49176, Count = 2)
            Template Id: 49176
            Field Count: 2
            Field (1/2):  18 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0001 0010 = Type: 18 [pen: CERT Coordination Center]
                Length: 65535 [i.e.: "Variable Length"]
                PEN: CERT Coordination Center (6871)
            Field (2/2): 16402 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .100 0000 0001 0010 = Type: 16402 [pen: CERT Coordination Center]
                Length: 65535 [i.e.: "Variable Length"]
                PEN: CERT Coordination Center (6871)
        Template (Id = 47104, Count = 39)
            Template Id: 47104
            Field Count: 39
            Field (1/39): flowStartMilliseconds
                0... .... .... .... = Pen provided: No
                .000 0000 1001 1000 = Type: flowStartMilliseconds (152)
                Length: 8
            Field (2/39): flowEndMilliseconds
                0... .... .... .... = Pen provided: No
                .000 0000 1001 1001 = Type: flowEndMilliseconds (153)
                Length: 8
            Field (3/39): BYTES_TOTAL
                0... .... .... .... = Pen provided: No
                .000 0000 0101 0101 = Type: BYTES_TOTAL (85)
                Length: 8
            Field (4/39): BYTES_TOTAL [Reverse]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0101 0101 = Type: BYTES_TOTAL (85) [Reverse]
                Length: 8
                PEN: IPFIX Reverse Information Element Private Enterprise (29305)
            Field (5/39): PACKETS_TOTAL
                0... .... .... .... = Pen provided: No
                .000 0000 0101 0110 = Type: PACKETS_TOTAL (86)
                Length: 8
            Field (6/39): PACKETS_TOTAL [Reverse]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0101 0110 = Type: PACKETS_TOTAL (86) [Reverse]
                Length: 8
                PEN: IPFIX Reverse Information Element Private Enterprise (29305)
            Field (7/39): BYTES
                0... .... .... .... = Pen provided: No
                .000 0000 0000 0001 = Type: BYTES (1)
                Length: 8
            Field (8/39): BYTES [Reverse]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0000 0001 = Type: BYTES (1) [Reverse]
                Length: 8
                PEN: IPFIX Reverse Information Element Private Enterprise (29305)
            Field (9/39): PKTS
                0... .... .... .... = Pen provided: No
                .000 0000 0000 0010 = Type: PKTS (2)
                Length: 8
            Field (10/39): PKTS [Reverse]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0000 0010 = Type: PKTS (2) [Reverse]
                Length: 8
                PEN: IPFIX Reverse Information Element Private Enterprise (29305)
            Field (11/39): IPV6_SRC_ADDR
                0... .... .... .... = Pen provided: No
                .000 0000 0001 1011 = Type: IPV6_SRC_ADDR (27)
                Length: 16
            Field (12/39): IPV6_DST_ADDR
                0... .... .... .... = Pen provided: No
                .000 0000 0001 1100 = Type: IPV6_DST_ADDR (28)
                Length: 16
            Field (13/39): IP_SRC_ADDR
                0... .... .... .... = Pen provided: No
                .000 0000 0000 1000 = Type: IP_SRC_ADDR (8)
                Length: 4
            Field (14/39): IP_DST_ADDR
                0... .... .... .... = Pen provided: No
                .000 0000 0000 1100 = Type: IP_DST_ADDR (12)
                Length: 4
            Field (15/39): L4_SRC_PORT
                0... .... .... .... = Pen provided: No
                .000 0000 0000 0111 = Type: L4_SRC_PORT (7)
                Length: 2
            Field (16/39): L4_DST_PORT
                0... .... .... .... = Pen provided: No
                .000 0000 0000 1011 = Type: L4_DST_PORT (11)
                Length: 2
            Field (17/39):  40 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0010 1000 = Type: 40 [pen: CERT Coordination Center]
                Length: 2
                PEN: CERT Coordination Center (6871)
            Field (18/39): 16424 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .100 0000 0010 1000 = Type: 16424 [pen: CERT Coordination Center]
                Length: 2
                PEN: CERT Coordination Center (6871)
            Field (19/39): PROTOCOL
                0... .... .... .... = Pen provided: No
                .000 0000 0000 0100 = Type: PROTOCOL (4)
                Length: 1
            Field (20/39): flowEndReason
                0... .... .... .... = Pen provided: No
                .000 0000 1000 1000 = Type: flowEndReason (136)
                Length: 1
            Field (21/39): paddingOctets
                0... .... .... .... = Pen provided: No
                .000 0000 1101 0010 = Type: paddingOctets (210)
                Length: 2
            Field (22/39):  21 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0001 0101 = Type: 21 [pen: CERT Coordination Center]
                Length: 4
                PEN: CERT Coordination Center (6871)
            Field (23/39): TCP_SEQ_NUM
                0... .... .... .... = Pen provided: No
                .000 0000 1011 1000 = Type: TCP_SEQ_NUM (184)
                Length: 4
            Field (24/39): TCP_SEQ_NUM [Reverse]
                1... .... .... .... = Pen provided: Yes
                .000 0000 1011 1000 = Type: TCP_SEQ_NUM (184) [Reverse]
                Length: 4
                PEN: IPFIX Reverse Information Element Private Enterprise (29305)
            Field (25/39):  14 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0000 1110 = Type: 14 [pen: CERT Coordination Center]
                Length: 1
                PEN: CERT Coordination Center (6871)
            Field (26/39):  15 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0000 1111 = Type: 15 [pen: CERT Coordination Center]
                Length: 1
                PEN: CERT Coordination Center (6871)
            Field (27/39): 16398 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .100 0000 0000 1110 = Type: 16398 [pen: CERT Coordination Center]
                Length: 1
                PEN: CERT Coordination Center (6871)
            Field (28/39): 16399 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .100 0000 0000 1111 = Type: 16399 [pen: CERT Coordination Center]
                Length: 1
                PEN: CERT Coordination Center (6871)
            Field (29/39): SRC_VLAN
                0... .... .... .... = Pen provided: No
                .000 0000 0011 1010 = Type: SRC_VLAN (58)
                Length: 2
            Field (30/39): SRC_VLAN [Reverse]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0011 1010 = Type: SRC_VLAN (58) [Reverse]
                Length: 2
                PEN: IPFIX Reverse Information Element Private Enterprise (29305)
            Field (31/39): INPUT_SNMP
                0... .... .... .... = Pen provided: No
                .000 0000 0000 1010 = Type: INPUT_SNMP (10)
                Length: 4
            Field (32/39): OUTPUT_SNMP
                0... .... .... .... = Pen provided: No
                .000 0000 0000 1110 = Type: OUTPUT_SNMP (14)
                Length: 4
            Field (33/39): IP_TOS
                0... .... .... .... = Pen provided: No
                .000 0000 0000 0101 = Type: IP_TOS (5)
                Length: 1
            Field (34/39): IP_TOS [Reverse]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0000 0101 = Type: IP_TOS (5) [Reverse]
                Length: 1
                PEN: IPFIX Reverse Information Element Private Enterprise (29305)
            Field (35/39): MPLS_LABEL_1
                0... .... .... .... = Pen provided: No
                .000 0000 0100 0110 = Type: MPLS_LABEL_1 (70)
                Length: 3
            Field (36/39): MPLS_LABEL_2
                0... .... .... .... = Pen provided: No
                .000 0000 0100 0111 = Type: MPLS_LABEL_2 (71)
                Length: 3
            Field (37/39): MPLS_LABEL_3
                0... .... .... .... = Pen provided: No
                .000 0000 0100 1000 = Type: MPLS_LABEL_3 (72)
                Length: 3
            Field (38/39): paddingOctets
                0... .... .... .... = Pen provided: No
                .000 0000 1101 0010 = Type: paddingOctets (210)
                Length: 5
            Field (39/39): subTemplateMultiList
                0... .... .... .... = Pen provided: No
                .000 0001 0010 0101 = Type: subTemplateMultiList (293)
                Length: 65535 [i.e.: "Variable Length"]
        Template (Id = 49155, Count = 3)
            Template Id: 49155
            Field Count: 3
            Field (1/3): TCP_SEQ_NUM
                0... .... .... .... = Pen provided: No
                .000 0000 1011 1000 = Type: TCP_SEQ_NUM (184)
                Length: 4
            Field (2/3):  14 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0000 1110 = Type: 14 [pen: CERT Coordination Center]
                Length: 1
                PEN: CERT Coordination Center (6871)
            Field (3/3):  15 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0000 1111 = Type: 15 [pen: CERT Coordination Center]
                Length: 1
                PEN: CERT Coordination Center (6871)
    Set 2 [id=3] (Options Template): 53248,53249
        FlowSet Id: Options Template (V10 [IPFIX]) (3)
        FlowSet Length: 124
        Options Template (Id = 53248) (Scope Count = 2; Data Count = 12)
            Template Id: 53248
            Total Field Count: 14
            Scope Field Count: 2
            Field (1/2) [Scope]: systemInitTimeMilliseconds
                0... .... .... .... = Pen provided: No
                .000 0000 1010 0000 = Type: systemInitTimeMilliseconds (160)
                Length: 8
            Field (2/2) [Scope]: TOTAL_FLOWS_EXP
                0... .... .... .... = Pen provided: No
                .000 0000 0010 1010 = Type: TOTAL_FLOWS_EXP (42)
                Length: 8
            Field (1/12): PACKETS_TOTAL
                0... .... .... .... = Pen provided: No
                .000 0000 0101 0110 = Type: PACKETS_TOTAL (86)
                Length: 8
            Field (2/12): DROPPED_PACKETS_TOTAL
                0... .... .... .... = Pen provided: No
                .000 0000 1000 0111 = Type: DROPPED_PACKETS_TOTAL (135)
                Length: 8
            Field (3/12): ignoredPacketTotalCount
                0... .... .... .... = Pen provided: No
                .000 0000 1010 0100 = Type: ignoredPacketTotalCount (164)
                Length: 8
            Field (4/12): notSentPacketTotalCount
                0... .... .... .... = Pen provided: No
                .000 0000 1010 0111 = Type: notSentPacketTotalCount (167)
                Length: 8
            Field (5/12): 100 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0110 0100 = Type: 100 [pen: CERT Coordination Center]
                Length: 4
                PEN: CERT Coordination Center (6871)
            Field (6/12): 101 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0110 0101 = Type: 101 [pen: CERT Coordination Center]
                Length: 4
                PEN: CERT Coordination Center (6871)
            Field (7/12): 104 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0110 1000 = Type: 104 [pen: CERT Coordination Center]
                Length: 4
                PEN: CERT Coordination Center (6871)
            Field (8/12): 105 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0110 1001 = Type: 105 [pen: CERT Coordination Center]
                Length: 4
                PEN: CERT Coordination Center (6871)
            Field (9/12): exporterIPv4Address
                0... .... .... .... = Pen provided: No
                .000 0000 1000 0010 = Type: exporterIPv4Address (130)
                Length: 4
            Field (10/12): FLOW_EXPORTER
                0... .... .... .... = Pen provided: No
                .000 0000 1001 0000 = Type: FLOW_EXPORTER (144)
                Length: 4
            Field (11/12): 102 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0110 0110 = Type: 102 [pen: CERT Coordination Center]
                Length: 4
                PEN: CERT Coordination Center (6871)
            Field (12/12): 103 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0110 0111 = Type: 103 [pen: CERT Coordination Center]
                Length: 4
                PEN: CERT Coordination Center (6871)
        Options Template (Id = 53249) (Scope Count = 2; Data Count = 2)
            Template Id: 53249
            Total Field Count: 4
            Scope Field Count: 2
            Field (1/2) [Scope]: 551 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0010 0010 0111 = Type: 551 [pen: CERT Coordination Center]
                Length: 2
                PEN: CERT Coordination Center (6871)
            Field (2/2) [Scope]: 552 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0010 0010 1000 = Type: 552 [pen: CERT Coordination Center]
                Length: 2
                PEN: CERT Coordination Center (6871)
            Field (1/2): 550 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0010 0010 0110 = Type: 550 [pen: CERT Coordination Center]
                Length: 4
                PEN: CERT Coordination Center (6871)
            Field (2/2): subTemplateList
                0... .... .... .... = Pen provided: No
                .000 0001 0010 0100 = Type: subTemplateList (292)
                Length: 65535 [i.e.: "Variable Length"]
    Set 3 [id=2] (Data Template): 53250,49156,49157,49161,49160
        FlowSet Id: Data Template (V10 [IPFIX]) (2)
        FlowSet Length: 172
        Template (Id = 53250, Count = 2)
            Template Id: 53250
            Field Count: 2
            Field (1/2): FLOW_EXPORTER
                0... .... .... .... = Pen provided: No
                .000 0000 1001 0000 = Type: FLOW_EXPORTER (144)
                Length: 4
            Field (2/2): observationTimeSeconds
                0... .... .... .... = Pen provided: No
                .000 0001 0100 0010 = Type: observationTimeSeconds (322)
                Length: 4
        Template (Id = 49156, Count = 2)
            Template Id: 49156
            Field Count: 2
            Field (1/2): SRC_MAC
                0... .... .... .... = Pen provided: No
                .000 0000 0011 1000 = Type: SRC_MAC (56)
                Length: 6
            Field (2/2): DESTINATION_MAC
                0... .... .... .... = Pen provided: No
                .000 0000 0101 0000 = Type: DESTINATION_MAC (80)
                Length: 6
        Template (Id = 49157, Count = 11)
            Template Id: 49157
            Field Count: 11
            Field (1/11): 502 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 0110 = Type: 502 [pen: CERT Coordination Center]
                Length: 8
                PEN: CERT Coordination Center (6871)
            Field (2/11): 503 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 0111 = Type: 503 [pen: CERT Coordination Center]
                Length: 8
                PEN: CERT Coordination Center (6871)
            Field (3/11): 504 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 1000 = Type: 504 [pen: CERT Coordination Center]
                Length: 8
                PEN: CERT Coordination Center (6871)
            Field (4/11): tcpUrgTotalCount
                0... .... .... .... = Pen provided: No
                .000 0000 1101 1111 = Type: tcpUrgTotalCount (223)
                Length: 4
            Field (5/11): 500 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 0100 = Type: 500 [pen: CERT Coordination Center]
                Length: 4
                PEN: CERT Coordination Center (6871)
            Field (6/11): 501 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 0101 = Type: 501 [pen: CERT Coordination Center]
                Length: 4
                PEN: CERT Coordination Center (6871)
            Field (7/11): 510 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 1110 = Type: 510 [pen: CERT Coordination Center]
                Length: 4
                PEN: CERT Coordination Center (6871)
            Field (8/11): 505 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 1001 = Type: 505 [pen: CERT Coordination Center]
                Length: 2
                PEN: CERT Coordination Center (6871)
            Field (9/11): 506 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 1010 = Type: 506 [pen: CERT Coordination Center]
                Length: 2
                PEN: CERT Coordination Center (6871)
            Field (10/11): 508 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 1100 = Type: 508 [pen: CERT Coordination Center]
                Length: 2
                PEN: CERT Coordination Center (6871)
            Field (11/11): 507 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 1111 1011 = Type: 507 [pen: CERT Coordination Center]
                Length: 1
                PEN: CERT Coordination Center (6871)
        Template (Id = 49161, Count = 5)
            Template Id: 49161
            Field Count: 5
            Field (1/5): 289 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 0010 0001 = Type: 289 [pen: CERT Coordination Center]
                Length: 8
                PEN: CERT Coordination Center (6871)
            Field (2/5): 290 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 0010 0010 = Type: 290 [pen: CERT Coordination Center]
                Length: 4
                PEN: CERT Coordination Center (6871)
            Field (3/5): 291 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 0010 0011 = Type: 291 [pen: CERT Coordination Center]
                Length: 2
                PEN: CERT Coordination Center (6871)
            Field (4/5): 292 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 0010 0100 = Type: 292 [pen: CERT Coordination Center]
                Length: 1
                PEN: CERT Coordination Center (6871)
            Field (5/5): 293 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0001 0010 0101 = Type: 293 [pen: CERT Coordination Center]
                Length: 1
                PEN: CERT Coordination Center (6871)
        Template (Id = 49160, Count = 1)
            Template Id: 49160
            Field Count: 1
            Field (1/1):  18 [pen: CERT Coordination Center]
                1... .... .... .... = Pen provided: Yes
                .000 0000 0001 0010 = Type: 18 [pen: CERT Coordination Center]
                Length: 65535 [i.e.: "Variable Length"]
                PEN: CERT Coordination Center (6871)
'''

data = "000a05875b6b68f5000088b200000000b30105770000015ded6dc31a0000015ded6dc32b00000528000000080ac8c91d12dcd028ad96005000000603000000ff000b03c003000a38334ace02190000015ded6dc31a0000015ded6dc32b000009b70000000712dcd0280ac8c91d0050ad9600000603000000ff000b03c003000a1745a14812190000015ded6dd6b80000015ded6dd6c300000528000000080ac8c91d12dcd028ad98005000000603000000ff000b03c003000a85b1530202190000015ded6dd6b90000015ded6dd6c3000009b70000000712dcd0280ac8c91d0050ad9800000603000000ff000b03c003000a3f3b674812190000015ded6dea500000015ded6dea5b00000531000000080ac8c91d12dcd028ad9a005000000603000000ff000b03c003000a026c56b402190000015ded6dea510000015ded6dea5b000009b70000000712dcd0280ac8c91d0050ad9a00000603000000ff000b03c003000acb867d0e12190000015ded6dfde80000015ded6dfdf200000531000000080ac8c91d12dcd028ad9c005000000603000000ff000b03c003000acb4dc8f502190000015ded6dfde90000015ded6dfdf2000009b70000000712dcd0280ac8c91d0050ad9c00000603000000ff000b03c003000a74f818c812190000015ded6e11800000015ded6e119400000528000000080ac8c91d12dcd028ad9e005000000603000000ff000b03c003000a929f7b7402190000015ded6e11800000015ded6e1194000009b70000000712dcd0280ac8c91d0050ad9e00000603000000ff000b03c003000ac86498bf12190000015ded6e25210000015ded6e252f0000052d000000080ac8c91d12dcd028ada0005000000603000000ff000b03c003000adbea55d802190000015ded6e25220000015ded6e252f000009b70000000712dcd0280ac8c91d0050ada000000603000000ff000b03c003000a886d0ec012190000015ded6e38b90000015ded6e38c400000528000000080ac8c91d12dcd028ada2005000000603000000ff000b03c003000a3dae2bc102190000015ded6e38ba0000015ded6e38c4000009b70000000712dcd0280ac8c91d0050ada200000603000000ff000b03c003000a452f533212190000015ded6e4c510000015ded6e4c6400000528000000080ac8c91d12dcd028ada4005000000603000000ff000b03c003000a0dbf625a02190000015ded6e4c510000015ded6e4c64000009b70000000712dcd0280ac8c91d0050ada400000603000000ff000b03c003000a3e60ed8012190000015ded69afe90000015ded69afe900000164000000010ac8c9010ac8c91d00000303000001010000c0ff0001030000015ded69afe80000015ded69bb7700000290000000020ac8c91d0ac8c9010044004300011101000000ff0001030000015ded69bb770000015ded69bb7700000166000000010ac8c9010ac8c91d0043004400001101000010ff0001030000015ded6e5fed0000015ded6e5ff800000528000000080ac8c91d12dcd028ada6005000000603000000ff000b03c003000a396b41ae02190000015ded6e5fee0000015ded6e5ff8000009b70000000712dcd0280ac8c91d0050ada600000603000000ff000b03c003000ae064716712190000015ded6e73860000015ded6e73980000052d000000080ac8c91d12dcd028ada8005000000603000000ff000b03c003000a2d7a9ea002190000015ded6e73860000015ded6e7398000009b70000000712dcd0280ac8c91d0050ada800000603000000ff000b03c003000ad64507af12190000015ded6e87250000015ded6e87300000052d000000080ac8c91d12dcd028adaa005000000603000000ff000b03c003000ae954052702190000015ded6e87260000015ded6e8730000009b70000000712dcd0280ac8c91d0050adaa00000603000000ff000b03c003000a4d792e001219".decode("hex")

'''
Cisco NetFlow/IPFIX
    Version: 10
    Length: 1415
    Timestamp: Aug  8, 2018 16:04:37.000000000 MDT
        ExportTime: 1533765877
    FlowSequence: 34994
    Observation Domain Id: 0
    Set 1 [id=45825] (25 flows)
        FlowSet Id: (Data) (45825)
        FlowSet Length: 1399
        [Template Frame: 214138]
        Flow 1
            [Duration: 0.017000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:42:59.866000000 MDT
                EndTime: Aug 16, 2017 17:42:59.883000000 MDT
            Permanent Octets: 1320
            Permanent Packets: 8
            SrcAddr: 10.200.201.29
            DstAddr: 18.220.208.40
            SrcPort: 44438
            DstPort: 80
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a 38 33 4a ce 02 19
                String_len_short: 255
                String_len_short: 11
        Flow 2
            [Duration: 0.017000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:42:59.866000000 MDT
                EndTime: Aug 16, 2017 17:42:59.883000000 MDT
            Permanent Octets: 2487
            Permanent Packets: 7
            SrcAddr: 18.220.208.40
            DstAddr: 10.200.201.29
            SrcPort: 80
            DstPort: 44438
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a 17 45 a1 48 12 19
                String_len_short: 255
                String_len_short: 11
        Flow 3
            [Duration: 0.011000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:04.888000000 MDT
                EndTime: Aug 16, 2017 17:43:04.899000000 MDT
            Permanent Octets: 1320
            Permanent Packets: 8
            SrcAddr: 10.200.201.29
            DstAddr: 18.220.208.40
            SrcPort: 44440
            DstPort: 80
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a 85 b1 53 02 02 19
        Flow 4
            [Duration: 0.010000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:04.889000000 MDT
                EndTime: Aug 16, 2017 17:43:04.899000000 MDT
            Permanent Octets: 2487
            Permanent Packets: 7
            SrcAddr: 18.220.208.40
            DstAddr: 10.200.201.29
            SrcPort: 80
            DstPort: 44440
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a 3f 3b 67 48 12 19
        Flow 5
            [Duration: 0.011000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:09.904000000 MDT
                EndTime: Aug 16, 2017 17:43:09.915000000 MDT
            Permanent Octets: 1329
            Permanent Packets: 8
            SrcAddr: 10.200.201.29
            DstAddr: 18.220.208.40
            SrcPort: 44442
            DstPort: 80
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a 02 6c 56 b4 02 19
        Flow 6
            [Duration: 0.010000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:09.905000000 MDT
                EndTime: Aug 16, 2017 17:43:09.915000000 MDT
            Permanent Octets: 2487
            Permanent Packets: 7
            SrcAddr: 18.220.208.40
            DstAddr: 10.200.201.29
            SrcPort: 80
            DstPort: 44442
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a cb 86 7d 0e 12 19
        Flow 7
            [Duration: 0.010000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:14.920000000 MDT
                EndTime: Aug 16, 2017 17:43:14.930000000 MDT
            Permanent Octets: 1329
            Permanent Packets: 8
            SrcAddr: 10.200.201.29
            DstAddr: 18.220.208.40
            SrcPort: 44444
            DstPort: 80
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a cb 4d c8 f5 02 19
        Flow 8
            [Duration: 0.009000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:14.921000000 MDT
                EndTime: Aug 16, 2017 17:43:14.930000000 MDT
            Permanent Octets: 2487
            Permanent Packets: 7
            SrcAddr: 18.220.208.40
            DstAddr: 10.200.201.29
            SrcPort: 80
            DstPort: 44444
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a 74 f8 18 c8 12 19
        Flow 9
            [Duration: 0.020000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:19.936000000 MDT
                EndTime: Aug 16, 2017 17:43:19.956000000 MDT
            Permanent Octets: 1320
            Permanent Packets: 8
            SrcAddr: 10.200.201.29
            DstAddr: 18.220.208.40
            SrcPort: 44446
            DstPort: 80
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a 92 9f 7b 74 02 19
        Flow 10
            [Duration: 0.020000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:19.936000000 MDT
                EndTime: Aug 16, 2017 17:43:19.956000000 MDT
            Permanent Octets: 2487
            Permanent Packets: 7
            SrcAddr: 18.220.208.40
            DstAddr: 10.200.201.29
            SrcPort: 80
            DstPort: 44446
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a c8 64 98 bf 12 19
        Flow 11
            [Duration: 0.014000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:24.961000000 MDT
                EndTime: Aug 16, 2017 17:43:24.975000000 MDT
            Permanent Octets: 1325
            Permanent Packets: 8
            SrcAddr: 10.200.201.29
            DstAddr: 18.220.208.40
            SrcPort: 44448
            DstPort: 80
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a db ea 55 d8 02 19
        Flow 12
            [Duration: 0.013000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:24.962000000 MDT
                EndTime: Aug 16, 2017 17:43:24.975000000 MDT
            Permanent Octets: 2487
            Permanent Packets: 7
            SrcAddr: 18.220.208.40
            DstAddr: 10.200.201.29
            SrcPort: 80
            DstPort: 44448
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a 88 6d 0e c0 12 19
        Flow 13
            [Duration: 0.011000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:29.977000000 MDT
                EndTime: Aug 16, 2017 17:43:29.988000000 MDT
            Permanent Octets: 1320
            Permanent Packets: 8
            SrcAddr: 10.200.201.29
            DstAddr: 18.220.208.40
            SrcPort: 44450
            DstPort: 80
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a 3d ae 2b c1 02 19
        Flow 14
            [Duration: 0.010000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:29.978000000 MDT
                EndTime: Aug 16, 2017 17:43:29.988000000 MDT
            Permanent Octets: 2487
            Permanent Packets: 7
            SrcAddr: 18.220.208.40
            DstAddr: 10.200.201.29
            SrcPort: 80
            DstPort: 44450
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a 45 2f 53 32 12 19
        Flow 15
            [Duration: 0.019000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:34.993000000 MDT
                EndTime: Aug 16, 2017 17:43:35.012000000 MDT
            Permanent Octets: 1320
            Permanent Packets: 8
            SrcAddr: 10.200.201.29
            DstAddr: 18.220.208.40
            SrcPort: 44452
            DstPort: 80
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a 0d bf 62 5a 02 19
        Flow 16
            [Duration: 0.019000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:34.993000000 MDT
                EndTime: Aug 16, 2017 17:43:35.012000000 MDT
            Permanent Octets: 2487
            Permanent Packets: 7
            SrcAddr: 18.220.208.40
            DstAddr: 10.200.201.29
            SrcPort: 80
            DstPort: 44452
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a 3e 60 ed 80 12 19
        Flow 17
            [Duration: 0.000000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:38:32.809000000 MDT
                EndTime: Aug 16, 2017 17:38:32.809000000 MDT
            Permanent Octets: 356
            Permanent Packets: 1
            SrcAddr: 10.200.201.1
            DstAddr: 10.200.201.29
            SrcPort: 0
            DstPort: 771
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: ICMP (1)
            Flow End Reason: Idle timeout (1)
            Vlan Id: 0
            IP ToS: 0xc0
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03
        Flow 18
            [Duration: 2.959000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:38:32.808000000 MDT
                EndTime: Aug 16, 2017 17:38:35.767000000 MDT
            Permanent Octets: 656
            Permanent Packets: 2
            SrcAddr: 10.200.201.29
            DstAddr: 10.200.201.1
            SrcPort: 68
            DstPort: 67
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 01
            Protocol: UDP (17)
            Flow End Reason: Idle timeout (1)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03
        Flow 19
            [Duration: 0.000000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:38:35.767000000 MDT
                EndTime: Aug 16, 2017 17:38:35.767000000 MDT
            Permanent Octets: 358
            Permanent Packets: 1
            SrcAddr: 10.200.201.1
            DstAddr: 10.200.201.29
            SrcPort: 67
            DstPort: 68
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: UDP (17)
            Flow End Reason: Idle timeout (1)
            Vlan Id: 0
            IP ToS: 0x10
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03
        Flow 20
            [Duration: 0.011000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:40.013000000 MDT
                EndTime: Aug 16, 2017 17:43:40.024000000 MDT
            Permanent Octets: 1320
            Permanent Packets: 8
            SrcAddr: 10.200.201.29
            DstAddr: 18.220.208.40
            SrcPort: 44454
            DstPort: 80
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a 39 6b 41 ae 02 19
        Flow 21
            [Duration: 0.010000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:40.014000000 MDT
                EndTime: Aug 16, 2017 17:43:40.024000000 MDT
            Permanent Octets: 2487
            Permanent Packets: 7
            SrcAddr: 18.220.208.40
            DstAddr: 10.200.201.29
            SrcPort: 80
            DstPort: 44454
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a e0 64 71 67 12 19
        Flow 22
            [Duration: 0.018000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:45.030000000 MDT
                EndTime: Aug 16, 2017 17:43:45.048000000 MDT
            Permanent Octets: 1325
            Permanent Packets: 8
            SrcAddr: 10.200.201.29
            DstAddr: 18.220.208.40
            SrcPort: 44456
            DstPort: 80
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a 2d 7a 9e a0 02 19
        Flow 23
            [Duration: 0.018000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:45.030000000 MDT
                EndTime: Aug 16, 2017 17:43:45.048000000 MDT
            Permanent Octets: 2487
            Permanent Packets: 7
            SrcAddr: 18.220.208.40
            DstAddr: 10.200.201.29
            SrcPort: 80
            DstPort: 44456
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a d6 45 07 af 12 19
        Flow 24
            [Duration: 0.011000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:50.053000000 MDT
                EndTime: Aug 16, 2017 17:43:50.064000000 MDT
            Permanent Octets: 1325
            Permanent Packets: 8
            SrcAddr: 10.200.201.29
            DstAddr: 18.220.208.40
            SrcPort: 44458
            DstPort: 80
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a e9 54 05 27 02 19
        Flow 25
            [Duration: 0.010000000 seconds (milliseconds)]
                StartTime: Aug 16, 2017 17:43:50.054000000 MDT
                EndTime: Aug 16, 2017 17:43:50.064000000 MDT
            Permanent Octets: 2487
            Permanent Packets: 7
            SrcAddr: 18.220.208.4
            DstAddr: 10.200.201.29
            SrcPort: 80
            DstPort: 44458
            Enterprise Private entry: (CERT Coordination Center) Type 40: Value (hex bytes): 00 00
            Protocol: TCP (6)
            Flow End Reason: End of Flow detected (3)
            Vlan Id: 0
            IP ToS: 0x00
            Enterprise Private entry: ((null)) Type 293: Value (hex bytes): 03 c0 03 00 0a 4d 79 2e 00 12 19
'''

host = sys.argv[1]
port = 2055
N = 150000
flowsPerPacket = 25

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(tpl, (host, port))

time.sleep(0.2)

ts = time.time()
print("%d: started sending %d YAF flows in %d packets totaling %d bytes" % (ts,N*flowsPerPacket, N, N*len(data)))
print("%d: flow size %d, packet size %d" % (ts, len(data) / flowsPerPacket, len(data)))

for i in range(0, N):
    sock.sendto(data, (host, port))
