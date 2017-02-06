# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "logstash/codecs/netflow"
require "json"

describe LogStash::Codecs::Netflow do
  subject do
    LogStash::Codecs::Netflow.new.tap do |codec|
      expect{codec.register}.not_to raise_error
    end
  end

  let(:decode) do
    [].tap do |events|
      data.each { |packet| subject.decode(packet){|event| events << event}}
    end
  end

  ### NETFLOW v5
 
  context "Netflow 5 valid 01" do
    let(:data) do
      # this netflow raw data was produced with softflowd and captured with netcat
      # softflowd -D -i eth0 -v 5 -t maxlife=1 -n 127.0.01:8765
      # nc -k -4 -u -l 127.0.0.1 8765 > netflow5.dat
      data = []
      data << IO.read(File.join(File.dirname(__FILE__), "netflow5.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@timestamp": "2015-05-02T18:38:08.280Z",
          "netflow": {
            "version": 5,
            "flow_seq_num": 0,
            "engine_type": 0,
            "engine_id": 0,
            "sampling_algorithm": 0,
            "sampling_interval": 0,
            "flow_records": 2,
            "ipv4_src_addr": "10.0.2.2",
            "ipv4_dst_addr": "10.0.2.15",
            "ipv4_next_hop": "0.0.0.0",
            "input_snmp": 0,
            "output_snmp": 0,
            "in_pkts": 5,
            "in_bytes": 230,
            "first_switched": "2015-06-21T11:40:52.280Z",
            "last_switched": "2015-05-02T18:38:08.279Z",
            "l4_src_port": 54435,
            "l4_dst_port": 22,
            "tcp_flags": 16,
            "protocol": 6,
            "src_tos": 0,
            "src_as": 0,
            "dst_as": 0,
            "src_mask": 0,
            "dst_mask": 0
          },
          "@version": "1"
        }
      END

      events << <<-END
        {
          "@timestamp": "2015-05-02T18:38:08.280Z",
          "netflow": {
            "version": 5,
            "flow_seq_num": 0,
            "engine_type": 0,
            "engine_id": 0,
            "sampling_algorithm": 0,
            "sampling_interval": 0,
            "flow_records": 2,
            "ipv4_src_addr": "10.0.2.15",
            "ipv4_dst_addr": "10.0.2.2",
            "ipv4_next_hop": "0.0.0.0",
            "input_snmp": 0,
            "output_snmp": 0,
            "in_pkts": 4,
            "in_bytes": 304,
            "first_switched": "2015-06-21T11:40:52.280Z",
            "last_switched": "2015-05-02T18:38:08.279Z",
            "l4_src_port": 22,
            "l4_dst_port": 54435,
            "tcp_flags": 24,
            "protocol": 6,
            "src_tos": 0,
            "src_as": 0,
            "dst_as": 0,
            "src_mask": 0,
            "dst_mask": 0
          },
          "@version": "1"
        }
      END

      events.map{|event| event.gsub(/\s+/, "")}
    end

    it "should decode raw data" do
      expect(decode.size).to eq(2)

      expect(decode[0].get("[netflow][version]")).to eq(5)
      expect(decode[0].get("[netflow][ipv4_src_addr]")).to eq("10.0.2.2")
      expect(decode[0].get("[netflow][ipv4_dst_addr]")).to eq("10.0.2.15")
      expect(decode[0].get("[netflow][l4_src_port]")).to eq(54435)
      expect(decode[0].get("[netflow][l4_dst_port]")).to eq(22)
      expect(decode[0].get("[netflow][tcp_flags]")).to eq(16)

      expect(decode[1].get("[netflow][version]")).to eq(5)
      expect(decode[1].get("[netflow][ipv4_src_addr]")).to eq("10.0.2.15")
      expect(decode[1].get("[netflow][ipv4_dst_addr]")).to eq("10.0.2.2")
      expect(decode[1].get("[netflow][l4_src_port]")).to eq(22)
      expect(decode[1].get("[netflow][l4_dst_port]")).to eq(54435)
      expect(decode[1].get("[netflow][tcp_flags]")).to eq(24)
    end

    it "should serialize to json" do
      # generated json order can change with different implementation, convert back to hash to compare.
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
      expect(JSON.parse(decode[1].to_json)).to eq(JSON.parse(json_events[1]))
    end
  end

  context "Netflow 5 invalid 01 " do
    let(:data) do
      data = []
      data << IO.read(File.join(File.dirname(__FILE__), "netflow5_test_invalid01.dat"), :mode => "rb")
    end

    it "should not raise_error " do
      expect{decode.size}.not_to raise_error
    end
  end

  context "Netflow 5 invalid 02 " do
    let(:data) do
      data = []
      data << IO.read(File.join(File.dirname(__FILE__), "netflow5_test_invalid02.dat"), :mode => "rb")
    end

    it "should not raise_error" do
      expect{decode.size}.not_to raise_error
    end
  end

  ### NETFLOW v9

  context "Netflow 9 valid 01" do
    let(:data) do
      # this netflow raw data was produced with softflowd and captured with netcat
      # softflowd -v 9 -n 172.16.32.202:2055
      # nc -4 -u -l 172.16.32.202 8765 > netflow9_test_valid01.dat
      data = []
      data << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_valid01.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@timestamp": "2015-10-08T19:04:30.000Z",
          "netflow": {
            "version": 9,
            "flow_seq_num":1,
            "flowset_id":1024,
            "ipv4_src_addr": "172.16.32.100",
            "ipv4_dst_addr":"172.16.32.248",
            "last_switched":"2015-10-08T19:03:47.999Z",
            "first_switched":"2015-10-08T19:03:47.999Z",
            "in_bytes":76,
            "in_pkts":1,
            "input_snmp":0,
            "output_snmp":0,
            "l4_src_port":123,
            "l4_dst_port":123,
            "protocol":17, 
            "tcp_flags":0,
            "ip_protocol_version":4,
            "src_tos":0
          },
          "@version": "1"
        }
      END

      events.map{|event| event.gsub(/\s+/, "")}

    end

    it "should decode raw data" do
      expect(decode.size).to eq(7)
      expect(decode[0].get("[netflow][version]")).to eq(9)
    end

    it "should serialize to json" do
      # generated json order can change with different implementation, convert back to hash to compare.
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end

  context "Netflow 9 macaddress" do
    let(:data) do
      data = []
      data << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_macaddr_tpl.dat"), :mode => "rb")
      data << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_macaddr_data.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@timestamp":"2015-10-10T08:47:01.000Z",
          "netflow":{
            "version":9,
            "flow_seq_num":2,
            "flowset_id":257,
            "protocol":6,
            "l4_src_port":65058,
            "ipv4_src_addr":"172.16.32.1",
            "l4_dst_port":22,
            "ipv4_dst_addr":"172.16.32.201",
            "in_src_mac":"00:50:56:c0:00:01",
            "in_dst_mac":"00:0c:29:70:86:09"
          },
          "@version":"1"
        }
      END

      events.map{|event| event.gsub(/\s+/, "")}
    end

    it "should decode the mac address" do
      expect(decode[1].get("[netflow][in_src_mac]")).to eq("00:50:56:c0:00:01")
      expect(decode[1].get("[netflow][in_dst_mac]")).to eq("00:0c:29:70:86:09")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[1].to_json)).to eq(JSON.parse(json_events[0]))
    end
  end

  context "Netflow 9 Cisco ASA" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_cisco_asa_1_tpl.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_cisco_asa_1_data.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@timestamp": "2015-10-09T09:47:51.000Z",
          "netflow": {
            "version": 9,
            "flow_seq_num": 662,
            "flowset_id": 265,
            "conn_id": 8501,
            "ipv4_src_addr": "192.168.23.22",
            "l4_src_port": 17549,
            "input_snmp": 2,
            "ipv4_dst_addr": "164.164.37.11",
            "l4_dst_port": 0,
            "output_snmp": 3,
            "protocol": 1,
            "icmp_type": 8,
            "icmp_code": 0,
            "xlate_src_addr_ipv4": "192.168.23.22",
            "xlate_dst_addr_ipv4": "164.164.37.11",
            "xlate_src_port": 17549,
            "xlate_dst_port": 0,
            "fw_event": 2,
            "fw_ext_event": 2025,
            "event_time_msec": 1444384070179,
            "in_permanent_bytes": 56,
            "flow_start_msec": 1444384068169,
            "ingress_acl_id": "0f8e7ff3-fc1a030f-00000000",
            "egress_acl_id": "00000000-00000000-00000000",
            "username": ""
          },
          "@version": "1"
        }
      END

      events.map{|event| event.gsub(/\s+/, "")}
    end

    it "should decode raw data" do
      expect(decode.size).to eq(14)
      expect(decode[1].get("[netflow][version]")).to eq(9)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[1].to_json)).to eq(JSON.parse(json_events[0]))
    end
  end

  context "Netflow 9 multple netflow exporters" do
    let(:data) do
      # This tests whether a template from a 2nd netflow exporter overwrites the template sent from the first.
      # In this test the 3rd packet (from nprobe) should still decode succesfully.
      # Note that in this case the SourceID from exporter 1 is different from exporter 2, otherwise we hit issue #9
      data = []
      data << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_nprobe_tpl.dat"), :mode => "rb")
      data << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_softflowd_tpl_data.dat"), :mode => "rb")
      data << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_nprobe_data.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@timestamp": "2015-10-08T19:04:30.000Z",
          "netflow": {
            "version":9,
            "flow_seq_num":1,
            "flowset_id":1024,
            "ipv4_src_addr":"172.16.32.100",
            "ipv4_dst_addr":"172.16.32.248",
            "last_switched":"2015-10-08T19:03:47.999Z",
            "first_switched":"2015-10-08T19:03:47.999Z",
            "in_bytes":76,
            "in_pkts":1,
            "input_snmp":0,
            "output_snmp":0,
            "l4_src_port":123,
            "l4_dst_port":123,
            "protocol":17,
            "tcp_flags":0,
            "ip_protocol_version":4,
            "src_tos":0
          },
          "@version":"1"
        }
      END

      events << <<-END
        {
          "@timestamp":"2015-10-08T19:06:29.000Z",
          "netflow": {
            "version":9,
            "flow_seq_num":1,
            "flowset_id":257,
            "in_bytes":200,
            "in_pkts":2,
            "protocol":6,
            "src_tos":16,
            "tcp_flags":24,
            "l4_src_port":22,
            "ipv4_src_addr":"172.16.32.201",
            "src_mask":0,
            "input_snmp":0,
            "l4_dst_port":65058,
            "ipv4_dst_addr":"172.16.32.1",
            "dst_mask":0,
            "output_snmp":0,
            "ipv4_next_hop":"0.0.0.0",
            "src_as":0,
            "dst_as":0,
            "last_switched":"2015-10-08T19:05:56.999Z",
            "first_switched":"2015-10-08T19:05:56.999Z"
          },
          "@version":"1"
        }
      END

      events.map{|event| event.gsub(/\s+/, "")}
    end

    # These tests will start to fail whenever options template decoding is added.
    # Nprobe includes options templates, which this test included a sample from.
    # Currently it is not decoded, but if it is, decode.size will be 9, and 
    # the packet currently identified with decode[7] will be decode[8]

    it "should decode raw data" do
      expect(decode.size).to eq(9)
      expect(decode[1].get("[netflow][l4_src_port]")).to eq(123)
      expect(decode[8].get("[netflow][l4_src_port]")).to eq(22)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[1].to_json)).to eq(JSON.parse(json_events[0]))
      expect(JSON.parse(decode[8].to_json)).to eq(JSON.parse(json_events[1]))
    end
  end

  context "Netflow 9 invalid 01 " do
    let(:data) do
      data = []
      data << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_invalid01.dat"), :mode => "rb")
    end

    it "should not raise_error" do
      expect{decode.size}.not_to raise_error
    end
  end

  context "Netflow 9 options template with scope fields" do
    let(:data) do
      data = []
      data << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_nprobe_tpl.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@timestamp":"2015-10-08T19:06:29.000Z",
          "netflow": {
              "version":9,
              "flow_seq_num":0,
              "flowset_id":259,
              "scope_system":0,
              "total_flows_exp":1,
              "total_pkts_exp":0
           },
           "@version":"1"
         }
      END

      events.map{|event| event.gsub(/\s+/, "")}
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
    end

    it "should decode raw data" do
      expect(decode[0].get("[netflow][scope_system]")).to eq(0)
      expect(decode[0].get("[netflow][total_flows_exp]")).to eq(1)
    end
  end

  context "IPFIX" do
    let(:data) do
      # this netflow raw data was produced with softflowd and captured with netcat
      # softflowd -D -i eth0 -v 10 -t maxlife=1 -n 127.0.01:8765
      # nc -k -4 -u -l 127.0.0.1 8765 > ipfix.dat
      data = []
      data << IO.read(File.join(File.dirname(__FILE__), "ipfix.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@timestamp": "2015-05-13T11:20:26.000Z",
          "netflow": {
            "version": 10,
            "meteringProcessId": 2679,
            "systemInitTimeMilliseconds": 1431516013506,
            "selectorAlgorithm": 1,
            "samplingPacketInterval": 1,
            "samplingPacketSpace": 0
          },
          "@version": "1"
        }
      END

      events << <<-END
        {
          "@timestamp": "2015-05-13T11:20:26.000Z",
          "netflow": {
            "version": 10,
            "sourceIPv4Address": "192.168.253.1",
            "destinationIPv4Address": "192.168.253.128",
            "octetDeltaCount": 260,
            "packetDeltaCount": 5,
            "ingressInterface": 0,
            "egressInterface": 0,
            "sourceTransportPort": 60560,
            "destinationTransportPort": 22,
            "protocolIdentifier": 6,
            "tcpControlBits": 16,
            "ipVersion": 4,
            "ipClassOfService": 0,
            "icmpTypeCodeIPv4": 0,
            "vlanId": 0,
            "flowStartSysUpTime": 0,
            "flowEndSysUpTime": 12726
          },
          "@version": "1"
        }
      END

      events << <<-END
        {
          "@timestamp": "2015-05-13T11:20:26.000Z",
          "netflow": {
            "version": 10,
            "sourceIPv4Address": "192.168.253.128",
            "destinationIPv4Address": "192.168.253.1",
            "octetDeltaCount": 1000,
            "packetDeltaCount": 6,
            "ingressInterface": 0,
            "egressInterface": 0,
            "sourceTransportPort": 22,
            "destinationTransportPort": 60560,
            "protocolIdentifier": 6,
            "tcpControlBits": 24,
            "ipVersion": 4,
            "ipClassOfService": 0,
            "icmpTypeCodeIPv4": 0,
            "vlanId": 0,
            "flowStartSysUpTime": 0,
            "flowEndSysUpTime": 12726
          },
          "@version": "1"
        }
      END

      events << <<-END
        {
          "@timestamp": "2015-05-13T11:20:26.000Z",
          "netflow": {
            "version": 10,
            "sourceIPv4Address": "192.168.253.2",
            "destinationIPv4Address": "192.168.253.132",
            "octetDeltaCount": 601,
            "packetDeltaCount": 2,
            "ingressInterface": 0,
            "egressInterface": 0,
            "sourceTransportPort": 53,
            "destinationTransportPort": 35262,
            "protocolIdentifier": 17,
            "tcpControlBits": 0,
            "ipVersion": 4,
            "ipClassOfService": 0,
            "icmpTypeCodeIPv4": 0,
            "vlanId": 0,
            "flowStartSysUpTime": 1104,
            "flowEndSysUpTime": 1142
          },
          "@version": "1"
        }
      END

      events << <<-END
        {
          "@timestamp": "2015-05-13T11:20:26.000Z",
          "netflow": {
            "version": 10,
            "sourceIPv4Address": "192.168.253.132",
            "destinationIPv4Address": "192.168.253.2",
            "octetDeltaCount": 148,
            "packetDeltaCount": 2,
            "ingressInterface": 0,
            "egressInterface": 0,
            "sourceTransportPort": 35262,
            "destinationTransportPort": 53,
            "protocolIdentifier": 17,
            "tcpControlBits": 0,
            "ipVersion": 4,
            "ipClassOfService": 0,
            "icmpTypeCodeIPv4": 0,
            "vlanId": 0,
            "flowStartSysUpTime": 1104,
            "flowEndSysUpTime": 1142
          },
          "@version": "1"
        }
      END

      events << <<-END
        {
          "@timestamp": "2015-05-13T11:20:26.000Z",
          "netflow": {
            "version": 10,
            "sourceIPv4Address": "54.214.9.161",
            "destinationIPv4Address": "192.168.253.132",
            "octetDeltaCount": 5946,
            "packetDeltaCount": 14,
            "ingressInterface": 0,
            "egressInterface": 0,
            "sourceTransportPort": 443,
            "destinationTransportPort": 49935,
            "protocolIdentifier": 6,
            "tcpControlBits": 26,
            "ipVersion": 4,
            "ipClassOfService": 0,
            "icmpTypeCodeIPv4": 0,
            "vlanId": 0,
            "flowStartSysUpTime": 1142,
            "flowEndSysUpTime": 2392
          },
          "@version": "1"
        }
      END

      events << <<-END
        {
          "@timestamp": "2015-05-13T11:20:26.000Z",
          "netflow": {
            "version": 10,
            "sourceIPv4Address": "192.168.253.132",
            "destinationIPv4Address": "54.214.9.161",
            "octetDeltaCount": 2608,
            "packetDeltaCount": 13,
            "ingressInterface": 0,
            "egressInterface": 0,
            "sourceTransportPort": 49935,
            "destinationTransportPort": 443,
            "protocolIdentifier": 6,
            "tcpControlBits": 26,
            "ipVersion": 4,
            "ipClassOfService": 0,
            "icmpTypeCodeIPv4": 0,
            "vlanId": 0,
            "flowStartSysUpTime": 1142,
            "flowEndSysUpTime": 2392
          },
          "@version": "1"
        }
      END

      events.map{|event| event.gsub(/\s+/, "")}
    end

    it "should decode raw data" do
      expect(decode.size).to eq(7)

      expect(decode[0].get("[netflow][version]")).to eq(10)
      expect(decode[0].get("[netflow][systemInitTimeMilliseconds]")).to eq(1431516013506)

      expect(decode[1].get("[netflow][version]")).to eq(10)
      expect(decode[1].get("[netflow][sourceIPv4Address]")).to eq("192.168.253.1")
      expect(decode[1].get("[netflow][destinationIPv4Address]")).to eq("192.168.253.128")
      expect(decode[1].get("[netflow][sourceTransportPort]")).to eq(60560)
      expect(decode[1].get("[netflow][destinationTransportPort]")).to eq(22)
      expect(decode[1].get("[netflow][protocolIdentifier]")).to eq(6)
      expect(decode[1].get("[netflow][tcpControlBits]")).to eq(16)

      expect(decode[2].get("[netflow][version]")).to eq(10)
      expect(decode[2].get("[netflow][sourceIPv4Address]")).to eq("192.168.253.128")
      expect(decode[2].get("[netflow][destinationIPv4Address]")).to eq("192.168.253.1")
      expect(decode[2].get("[netflow][sourceTransportPort]")).to eq(22)
      expect(decode[2].get("[netflow][destinationTransportPort]")).to eq(60560)
      expect(decode[2].get("[netflow][protocolIdentifier]")).to eq(6)
      expect(decode[2].get("[netflow][tcpControlBits]")).to eq(24)

      expect(decode[3].get("[netflow][sourceIPv4Address]")).to eq("192.168.253.2")
      expect(decode[3].get("[netflow][destinationIPv4Address]")).to eq("192.168.253.132")
      expect(decode[3].get("[netflow][sourceTransportPort]")).to eq(53)
      expect(decode[3].get("[netflow][destinationTransportPort]")).to eq(35262)
      expect(decode[3].get("[netflow][protocolIdentifier]")).to eq(17)

      expect(decode[4].get("[netflow][sourceIPv4Address]")).to eq("192.168.253.132")
      expect(decode[4].get("[netflow][destinationIPv4Address]")).to eq("192.168.253.2")
      expect(decode[4].get("[netflow][sourceTransportPort]")).to eq(35262)
      expect(decode[4].get("[netflow][destinationTransportPort]")).to eq(53)
      expect(decode[4].get("[netflow][protocolIdentifier]")).to eq(17)

      expect(decode[5].get("[netflow][sourceIPv4Address]")).to eq("54.214.9.161")
      expect(decode[5].get("[netflow][destinationIPv4Address]")).to eq("192.168.253.132")
      expect(decode[5].get("[netflow][sourceTransportPort]")).to eq(443)
      expect(decode[5].get("[netflow][destinationTransportPort]")).to eq(49935)
      expect(decode[5].get("[netflow][protocolIdentifier]")).to eq(6)
      expect(decode[5].get("[netflow][tcpControlBits]")).to eq(26)

      expect(decode[6].get("[netflow][sourceIPv4Address]")).to eq("192.168.253.132")
      expect(decode[6].get("[netflow][destinationIPv4Address]")).to eq("54.214.9.161")
      expect(decode[6].get("[netflow][sourceTransportPort]")).to eq(49935)
      expect(decode[6].get("[netflow][destinationTransportPort]")).to eq(443)
      expect(decode[6].get("[netflow][protocolIdentifier]")).to eq(6)
      expect(decode[6].get("[netflow][tcpControlBits]")).to eq(26)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
      expect(JSON.parse(decode[1].to_json)).to eq(JSON.parse(json_events[1]))
      expect(JSON.parse(decode[2].to_json)).to eq(JSON.parse(json_events[2]))
      expect(JSON.parse(decode[3].to_json)).to eq(JSON.parse(json_events[3]))
      expect(JSON.parse(decode[4].to_json)).to eq(JSON.parse(json_events[4]))
      expect(JSON.parse(decode[5].to_json)).to eq(JSON.parse(json_events[5]))
      expect(JSON.parse(decode[6].to_json)).to eq(JSON.parse(json_events[6]))
    end

  end

  context "Netflow 9 Cisco ASA #2" do
    let(:data) do
      # The ASA sent 2 packets with templates, 260-270, and 270-280
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_cisco_asa_2_tpl_26x.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_cisco_asa_2_tpl_27x.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_cisco_asa_2_data.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@timestamp": "2016-07-21T13:50:37.000Z",
          "netflow": {
            "version": 9,
            "flow_seq_num": 31,
            "flowset_id": 263,
            "conn_id": 742820223,
            "ipv4_src_addr": "192.168.0.1",
            "l4_src_port":56651,
            "input_snmp":3,
            "ipv4_dst_addr":"192.168.0.18",
            "l4_dst_port":80,
            "output_snmp":4,
            "protocol":6,
            "icmp_type":0,
            "icmp_code":0,
            "xlate_src_addr_ipv4":"192.168.0.1",
            "xlate_dst_addr_ipv4":"192.168.0.18",
            "xlate_src_port":56651,
            "xlate_dst_port":80,
            "fw_event":2,
            "fw_ext_event":2030,
            "event_time_msec":1469109036495,
            "fwd_flow_delta_bytes":69,
            "rev_flow_delta_bytes":14178,
            "flow_start_msec":1469109036395
          },
          "@version": "1"
        }
        END
      events.map{|event| event.gsub(/\s+/, "")}
    end

    it "should decode raw data" do
      expect(decode.size).to eq(19)
      expect(decode[18].get("[netflow][ipv4_src_addr]")).to eq("192.168.0.1")
      expect(decode[18].get("[netflow][ipv4_dst_addr]")).to eq("192.168.0.18")
      expect(decode[18].get("[netflow][fwd_flow_delta_bytes]")).to eq(69)
      expect(decode[18].get("[netflow][conn_id]")).to eq(742820223)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[18].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end

  context "IPFIX OpenBSD pflow" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_openbsd_pflow_tpl.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_openbsd_pflow_data.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@timestamp": "2016-07-21T13:30:37.000Z",
          "netflow": {
            "version": 10,
            "sourceIPv4Address": "192.168.0.1",
            "destinationIPv4Address": "192.168.0.17",
            "ingressInterface": 1,
            "egressInterface": 1,
            "packetDeltaCount": 8,
            "octetDeltaCount": 6425,
            "flowStartMilliseconds": "2016-07-21T13:29:59.000Z",
            "flowEndMilliseconds": "2016-07-21T13:30:01.000Z",
            "sourceTransportPort": 80,
            "destinationTransportPort": 64026,
            "ipClassOfService": 0,
            "protocolIdentifier": 6
          },
          "@version": "1"
        }
        END
      events.map{|event| event.gsub(/\s+/, "")}
    end

    it "should decode raw data" do
      expect(decode.size).to eq(26)
      expect(decode[25].get("[netflow][sourceIPv4Address]")).to eq("192.168.0.1")
      expect(decode[25].get("[netflow][destinationIPv4Address]")).to eq("192.168.0.17")
      expect(decode[25].get("[netflow][octetDeltaCount]")).to eq(6425)
      expect(decode[25].get("[netflow][destinationTransportPort]")).to eq(64026)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[25].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end

  context "Netflow5 microtik" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow5_test_microtik.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@timestamp": "2016-07-21T13:51:57.514Z",
          "netflow": {
            "version": 5,
            "flow_seq_num": 8140050,
            "engine_type": 0,
            "engine_id": 0,
            "sampling_algorithm": 0,
            "sampling_interval": 0,
            "flow_records": 30,
            "ipv4_src_addr": "10.0.8.1",
            "ipv4_dst_addr": "192.168.0.1",
            "ipv4_next_hop": "192.168.0.1",
            "input_snmp": 13,
            "output_snmp": 46,
            "in_pkts": 13,
            "in_bytes": 11442,
            "first_switched": "2016-07-21T13:51:42.514Z",
            "last_switched": "2016-07-21T13:51:42.514Z",
            "l4_src_port": 80,
            "l4_dst_port": 51826,
            "tcp_flags": 82,
            "protocol": 6,
            "src_tos": 40,
            "src_as": 0,
            "dst_as": 0,
            "src_mask": 0,
            "dst_mask": 0
          },
          "@version": "1"
        }
        END
      events.map{|event| event.gsub(/\s+/, "")}
    end

    it "should decode raw data" do
      expect(decode.size).to eq(30)
      expect(decode[29].get("[netflow][ipv4_src_addr]")).to eq("10.0.8.1")
      expect(decode[29].get("[netflow][ipv4_dst_addr]")).to eq("192.168.0.1")
      expect(decode[29].get("[netflow][l4_dst_port]")).to eq(51826)
      expect(decode[29].get("[netflow][src_tos]")).to eq(40)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[29].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end

  context "Netflow5 Juniper MX80" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow5_test_juniper_mx80.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@timestamp": "2016-07-21T13:52:52.000Z",
          "netflow": {
            "version": 5,
            "flow_seq_num": 528678,
            "engine_type": 0,
            "engine_id": 0,
            "sampling_algorithm": 0,
            "sampling_interval": 1000,
            "flow_records": 29,
            "ipv4_src_addr": "66.249.92.75",
            "ipv4_dst_addr": "192.168.0.1",
            "ipv4_next_hop": "192.168.0.1",
            "input_snmp": 542,
            "output_snmp": 536,
            "in_pkts": 2,
            "in_bytes": 104,
            "first_switched": "2016-07-21T13:52:34.999Z",
            "last_switched": "2016-07-21T13:52:34.999Z",
            "l4_src_port": 37387,
            "l4_dst_port": 80,
            "tcp_flags": 16,
            "protocol": 6,
            "src_tos": 0,
            "src_as": 15169,
            "dst_as": 64496,
            "src_mask": 19,
            "dst_mask": 24
          },
          "@version": "1"
        }
        END
      events.map{|event| event.gsub(/\s+/, "")}
    end

    it "should decode raw data" do
      expect(decode.size).to eq(29)
      expect(decode[28].get("[netflow][ipv4_src_addr]")).to eq("66.249.92.75")
      expect(decode[28].get("[netflow][ipv4_dst_addr]")).to eq("192.168.0.1")
      expect(decode[28].get("[netflow][l4_dst_port]")).to eq(80)
      expect(decode[28].get("[netflow][src_as]")).to eq(15169)
      expect(decode[28].get("[netflow][dst_as]")).to eq(64496)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[28].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end

  context "Netflow 9 Ubiquiti Edgerouter with MPLS labels" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_ubnt_edgerouter_tpl.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_ubnt_edgerouter_data1024.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_ubnt_edgerouter_data1025.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@timestamp": "2016-09-10T16:24:08.000Z", 
          "netflow": {
            "output_snmp": 4, 
            "out_src_mac": "06:be:ef:be:ef:b9", 
            "in_pkts": 21, 
            "ip_protocol_version": 4, 
            "ipv4_dst_addr": "10.2.0.95",
            "src_tos": 0, 
            "first_switched": "2016-09-10T15:02:54.999Z", 
            "flowset_id": 1025, 
            "l4_src_port": 47690, 
            "out_dst_mac": "44:d9:e7:be:ef:8e", 
            "version": 9, 
            "flow_seq_num": 31664, 
            "ipv4_src_addr": "192.168.1.102", 
            "in_bytes": 3668, 
            "protocol": 6, 
            "mpls_label_stack_octets": { 
              "bottom_of_stack": 0, 
              "experimental": 0, 
              "label": 0, 
              "ttl": 4
            }, 
            "last_switched": "2016-09-10T15:23:45.999Z", 
            "input_snmp": 2, 
            "flows": 0, 
            "tcp_flags": 27, 
            "dst_vlan": 0, 
            "l4_dst_port": 443, 
            "direction": 1
          },
          "@version": "1"
        }
        END
      events.map{|event| event.gsub(/\s+/, "")}
    end

    it "should decode raw data" do
      expect(decode.size).to eq(16)
      expect(decode[0].get("[netflow][ipv4_src_addr]")).to eq("10.1.0.135")
      expect(decode[15].get("[netflow][ipv4_src_addr]")).to eq("192.168.1.102")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[15].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end

  context "Netflow 9 Streamcore" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_streamcore_tpl_data256.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_streamcore_tpl_data260.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "netflow": {
            "in_pkts": 3,
            "first_switched": "2017-01-11T11:47:23.999Z",
            "flowset_id": 256,
            "l4_src_port": 8080,
            "streamcore_id_rule_1": 1171,
            "streamcore_id_rule_2": 1179,
            "in_bytes": 128,
            "protocol": 6,
            "streamcore_id_rule_5": 0,
            "tcp_flags": 19,
            "streamcore_id_rule_3": 1192,
            "streamcore_id_rule_4": 1435,
            "streamcore_net_app_resp_time": 0,
            "l4_dst_port": 50073,
            "output_snmp": 1148,
            "streamcore_call_direction": 1,
            "src_tos": 40,
            "ipv4_dst_addr": "10.231.128.150",
            "version": 9,
            "streamcore_tcp_retrans_rate": 0,
            "flow_seq_num": 2143054578,
            "ipv4_src_addr": "100.78.40.201",
            "input_snmp": 1152,
            "last_switched": "2017-01-11T11:47:29.999Z",
            "streamcore_wan_rtt": 0,
            "streamcore_total_app_resp_time": 0
          },
          "@timestamp": "2017-01-11T11:48:15.000Z",
          "@version": "1"
        }
      END

      events << <<-END
        {
          "netflow": {
            "in_pkts": 4,
            "first_switched": "2017-01-11T11:47:23.999Z",
            "flowset_id": 256,
            "l4_src_port": 50073,
            "streamcore_id_rule_1": 1171,
            "streamcore_id_rule_2": 1179,
            "in_bytes": 172,
            "protocol": 6,
            "streamcore_id_rule_5": 0,
            "tcp_flags": 19,
            "streamcore_id_rule_3": 1192,
            "streamcore_id_rule_4": 1435,
            "streamcore_net_app_resp_time": 0,
            "l4_dst_port": 8080,
            "output_snmp": 1152,
            "streamcore_call_direction": 0,
            "src_tos": 40,
            "ipv4_dst_addr": "100.78.40.201",
            "version": 9,
            "streamcore_tcp_retrans_rate": 0,
            "flow_seq_num": 2143054578,
            "ipv4_src_addr": "10.231.128.150",
            "input_snmp": 1148,
            "last_switched": "2017-01-11T11:47:29.999Z",
            "streamcore_wan_rtt": 0,
            "streamcore_total_app_resp_time": 0
          },
          "@timestamp": "2017-01-11T11:48:15.000Z",
          "@version": "1"
        }
      END

      events << <<-END
        {
          "netflow": {
            "streamcore_id_rule_10": 0,
            "in_pkts": 10,
            "first_switched": "2017-01-11T11:22:44.999Z",
            "flowset_id": 260,
            "l4_src_port": 8080,
            "reamcore_id_rule_1": 1171,
            "streamcore_id_rule_2": 1179,
            "in_bytes": 3943,
            "protocol": 6,
            "streamcore_id_rule_5": 0,
            "tcp_flags": 26,
            "streamcore_id_rule_6": 0,
            "streamcore_id_rule_3": 1192,
            "streamcore_id_rule_4": 1435,
            "streamcore_id_rule_9": 0,
            "streamcore_id_rule_7": 0,
            "streamcore_id_rule_8": 0,
            "streamcore_net_app_resp_time": 17,
            "l4_dst_port": 53483,
            "output_snmp": 1148,
            "streamcore_hostname": "live.lemde.fr",
            "streamcore_call_direction": 1,
            "src_tos": 40,
            "ipv4_dst_addr": "10.27.8.20",
            "version": 9,
            "streamcore_tcp_retrans_rate": 0,
            "flow_seq_num": 2142545188,
            "ipv4_src_addr": "100.78.40.201",
            "input_snmp": 1152,
            "last_switched": "2017-01-11T11:23:35.999Z",
            "streamcore_url": "\/mux.json",
            "streamcore_wan_rtt": 0,
            "streamcore_total_app_resp_time": 19
          },
          "@timestamp": "2017-01-11T11:23:51.000Z",
          "@version": "1"
        }
      END

      events << <<-END
        {
          "netflow": {
            "streamcore_id_rule_10": 0,
            "in_pkts": 11,
            "first_switched": "2017-01-11T11:22:44.999Z",
            "flowset_id": 260,
            "l4_src_port": 53483,
            "streamcore_id_rule_1": 1171,
            "streamcore_id_rule_2": 1179,
            "in_bytes": 3052,
            "protocol": 6,
            "streamcore_id_rule_5": 0,
            "tcp_flags": 26,
            "streamcore_id_rule_6": 0,
            "streamcore_id_rule_3": 1192,
            "streamcore_id_rule_4": 1435,
            "streamcore_id_rule_9": 0,
            "streamcore_id_rule_7": 0,
            "streamcore_id_rule_8": 0,
            "streamcore_net_app_resp_time": 17,
            "l4_dst_port": 8080,
            "output_snmp": 1152,
            "streamcore_hostname": "live.lemde.fr",
            "streamcore_call_direction": 0,
            "src_tos": 40,
            "ipv4_dst_addr": "100.78.40.201",
            "version": 9,
            "streamcore_tcp_retrans_rate": 0,
            "flow_seq_num": 2142545188,
            "ipv4_src_addr": "10.27.8.20",
            "input_snmp": 1148,
            "last_switched": "2017-01-11T11:23:35.999Z",
            "streamcore_url": "\/mux.json",
            "streamcore_wan_rtt": 0,
            "streamcore_total_app_resp_time": 19
          },
          "@timestamp": "2017-01-11T11:23:51.000Z",
          "@version": "1"
        }
      END

      events.map{|event| event.gsub(/\s+/, "")}
    end

    it "should decode raw data" do
      expect(decode.size).to eq(4)
      expect(decode[0].get("[netflow][streamcore_id_rule_1]")).to eq(1171)
      expect(decode[3].get("[netflow][streamcore_hostname]")).to eq("live.lemde.fr")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
      expect(JSON.parse(decode[3].to_json)).to eq(JSON.parse(json_events[3]))
    end

  end


  context "IPFIX Netscaler with variable length fields" do
    let(:data) do
      # this ipfix raw data was produced by a Netscaler appliance and captured with wireshark
      # select packet bytes were then exported and sort of Pseudonymized to protect corp data
      data = []
      data << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_netscaler_tpl.dat"), :mode => "rb")
      data << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_netscaler_data.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@timestamp": "2016-11-11T12:09:19.000Z",
          "netflow": {
            "netscalerHttpReqUserAgent": "Mozilla/5.0 (Commodore 64;  kobo.com) Gecko/20100101 Firefox/75.0",
            "destinationTransportPort": 443,
            "netscalerHttpReqCookie": "beer=123456789abcdefghijklmnopqrstuvw; AnotherCookie=1234567890abcdefghijklmnopqr; Shameless.Plug=Thankyou.Rakuten.Kobo.Inc.For.Allowing.me.time.to.work.on.this.and.contribute.back.to.the.community; Padding=aaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbccccccccccccccddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeffffffffffffffffffffffgggggggggggggggggggggggghhhhhhhhhhhhhhhhhiiiiiiiiiiiiiiiiiiiiiijjjjjjjjjjjjjjjjjjjjjjjjkkkkkkkkkkkkkkkkkklllllllllllllllmmmmmmmmmm; more=less; GJquote=There.is.no.spoon; GarrySays=Nice!!; LastPadding=aaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbcccccccccccccccccccdddddddddddeeeeeeee",
            "flowEndMicroseconds": "2016-11-11T12:09:19.000Z",
            "netscalerHttpReqUrl": "/aa/bb/ccccc/ddddddddddddddddddddddddd",
            "sourceIPv4Address": "192.168.0.1",
            "netscalerHttpReqMethod": "GET",
            "netscalerHttpReqHost": "www.kobo.com",
            "egressInterface": 2147483651,
            "octetDeltaCount": 1541,
            "netscalerAppNameAppId": 240189440,
            "sourceTransportPort": 51053,
            "flowId": 14460661,
            "netscalerHttpReqAuthorization": "",
            "netscalerHttpDomainName": "www.kobo.com",
            "netscalerAaaUsername": "",
            "netscalerHttpContentType": "",
            "destinationIPv4Address": "10.0.0.1",
            "observationPointId": 167954698,
            "netscalerHttpReqVia": "1.1 akamai.net(ghost) (AkamaiGHost)",
            "netscalerConnectionId": 14460661,
            "tcpControlBits": 24,
            "flowStartMicroseconds": "2016-11-11T12:09:19.000Z",
            "ingressInterface": 8,
            "version": 10,
            "packetDeltaCount": 2,
            "netscalerUnknown330": 0,
            "netscalerConnectionChainID": "00e0ed1c9ca80300efb42558596b0800",
            "ipVersion": 4,
            "protocolIdentifier": 6,
            "netscalerHttpResForwLB": 0,
            "netscalerHttpReqReferer": "http://www.kobo.com/is-the-best-ebook-company-in-the-world",
            "exportingProcessId": 3,
            "netscalerAppUnitNameAppId": 239927296,
            "netscalerFlowFlags": 84025344,
            "netscalerTransactionId": 1068114985,
            "netscalerHttpResForwFB": 0,
            "netscalerConnectionChainHopCount": 1,
            "netscalerHttpReqXForwardedFor": "11.222.33.255"
          },
          "@version": "1"
        }
        END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(3)
      expect(decode[0].get("[netflow][version]")).to eq(10)
      expect(decode[0].get("[netflow][sourceIPv4Address]")).to eq('192.168.0.1')
      expect(decode[0].get("[netflow][destinationIPv4Address]")).to eq('10.0.0.1')
      expect(decode[0].get("[netflow][flowEndMicroseconds]")).to eq('2016-11-11T12:09:19.000Z')
      expect(decode[0].get("[netflow][netscalerConnectionId]")).to eq(14460661)
      expect(decode[1].get("[netflow][version]")).to eq(10)
      expect(decode[1].get("[netflow][flowId]")).to eq(14460662)
      expect(decode[1].get("[netflow][observationPointId]")).to eq(167954698)
      expect(decode[1].get("[netflow][netscalerFlowFlags]")).to eq(1157636096)
      expect(decode[1].get("[netflow][netscalerRoundTripTime]")).to eq(83)
      expect(decode[2].get("[netflow][version]")).to eq(10)
      expect(decode[2].get("[netflow][netscalerAppUnitNameAppId]")).to eq(239927296)
      expect(decode[2].get("[netflow][netscalerHttpReqXForwardedFor]")).to eq('11.222.33.255')
    end

    it "should decode variable length fields" do
      expect(decode[2].get("[netflow][netscalerHttpReqUrl]")).to eq('/aa/bb/ccccc/ddddddddddddddddddddddddd')
      expect(decode[2].get("[netflow][netscalerHttpReqHost]")).to eq('www.kobo.com')
      expect(decode[2].get("[netflow][netscalerHttpReqUserAgent]")).to eq('Mozilla/5.0 (Commodore 64;  kobo.com) Gecko/20100101 Firefox/75.0')
      expect(decode[2].get("[netflow][netscalerHttpReqVia]")).to eq('1.1 akamai.net(ghost) (AkamaiGHost)')
    end

    it "should decode fields with more than 255 chars" do
      expect(decode[2].get("[netflow][netscalerHttpReqCookie]")).to eq('beer=123456789abcdefghijklmnopqrstuvw; AnotherCookie=1234567890abcdefghijklmnopqr; Shameless.Plug=Thankyou.Rakuten.Kobo.Inc.For.Allowing.me.time.to.work.on.this.and.contribute.back.to.the.community; Padding=aaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbccccccccccccccddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeffffffffffffffffffffffgggggggggggggggggggggggghhhhhhhhhhhhhhhhhiiiiiiiiiiiiiiiiiiiiiijjjjjjjjjjjjjjjjjjjjjjjjkkkkkkkkkkkkkkkkkklllllllllllllllmmmmmmmmmm; more=less; GJquote=There.is.no.spoon; GarrySays=Nice!!; LastPadding=aaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbcccccccccccccccccccdddddddddddeeeeeeee')
    end

    it "should decode octetarray data" do
      expect(decode[0].get("[netflow][netscalerConnectionChainID]")).to eq('00e0ed1c9ca80300efb4255884850600')
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[2].to_json)).to eq(JSON.parse(json_events[0]))
    end
  end

  context "IPFIX VMware virtual distributed switch" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_vmware_vds_tpl.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_vmware_vds_data264.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_vmware_vds_data266.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_vmware_vds_data266_267.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
      {
        "netflow": {
          "destinationIPv4Address": "172.18.65.211",
          "destinationTransportPort": 5985,
          "tcpControlBits": 2,
          "vmwareUnknown890": 1,
          "sourceIPv4Address": "172.18.65.21",
          "ingressInterface": 3,
          "ipClassOfService": 0,
          "version": 10,
          "packetDeltaCount": 2,
          "flowEndReason": 1,
          "protocolIdentifier": 6,
          "flowDirection": 1,
          "layer2SegmentId": 0,
          "egressInterface": 11,
          "octetDeltaCount": 100,
          "sourceTransportPort": 61209,
          "flowEndMilliseconds": "2016-12-22T12:17:37.000Z",
          "maximumTTL": 128,
          "vmwareUnknown888": 2,
          "flowStartMilliseconds": "2016-12-22T12:17:37.000Z",
          "vmwareUnknown889": 0
        },
        "@timestamp": "2016-12-22T12:17:52.000Z",
        "@version": "1"
      }
      END

      events << <<-END
      {
        "netflow": {
          "destinationIPv4Address": "172.18.65.255",
          "destinationTransportPort": 138,
          "tcpControlBits": 0,
          "vmwareUnknown890": 1,
          "sourceIPv4Address": "172.18.65.91",
          "ingressInterface": 2,
          "ipClassOfService": 0,
          "version": 10,
          "packetDeltaCount": 1,
          "flowEndReason": 1,
          "protocolIdentifier": 17,
          "flowDirection": 1,
          "layer2SegmentId": 0,
          "egressInterface": 10,
          "octetDeltaCount": 229,
          "sourceTransportPort": 138,
          "flowEndMilliseconds": "2016-12-22T12:17:42.000Z",
          "maximumTTL": 128,
          "vmwareUnknown888": 2,
          "flowStartMilliseconds": "2016-12-22T12:17:42.000Z",
          "vmwareUnknown889": 0
        },
        "@timestamp": "2016-12-22T12:17:56.000Z",
        "@version": "1"
      }
      END

      events << <<-END
      {
        "netflow": {
          "destinationIPv4Address": "172.18.65.255",
          "destinationTransportPort": 138,
          "tcpControlBits": 0,
          "vmwareUnknown890": 1,
          "sourceIPv4Address": "172.18.65.91",
          "ingressInterface": 3,
          "ipClassOfService": 0,
          "version": 10,
          "packetDeltaCount": 1,
          "flowEndReason": 1,
          "protocolIdentifier": 17,
          "flowDirection": 1,
          "layer2SegmentId": 0,
          "egressInterface": 11,
          "octetDeltaCount": 229,
          "sourceTransportPort": 138,
          "flowEndMilliseconds": "2016-12-22T12:17:42.000Z",
          "maximumTTL": 128,
          "vmwareUnknown888": 2,
          "flowStartMilliseconds": "2016-12-22T12:17:42.000Z",
          "vmwareUnknown889": 0
        },
        "@timestamp": "2016-12-22T12:17:56.000Z",
        "@version": "1"
      }
      END

      events << <<-END
      {
        "netflow": {
          "destinationIPv4Address": "224.0.0.252",
          "destinationTransportPort": 5355,
          "tcpControlBits": 0,
          "vmwareUnknown890": 1,
          "sourceIPv4Address": "172.18.65.21",
          "ingressInterface": 3,
          "ipClassOfService": 0,
          "version": 10,
          "packetDeltaCount": 2,
          "flowEndReason": 1,
          "protocolIdentifier": 17,
          "flowDirection": 1,
          "layer2SegmentId": 0,
          "egressInterface": 11,
          "octetDeltaCount": 104,
          "sourceTransportPort": 61329,
          "flowEndMilliseconds": "2016-12-22T12:25:49.000Z",
          "maximumTTL": 1,
          "vmwareUnknown888": 2,
          "flowStartMilliseconds": "2016-12-22T12:25:49.000Z",
          "vmwareUnknown889": 0
        },
        "@timestamp": "2016-12-22T12:26:04.000Z",
        "@version": "1"
      }
      END

      events << <<-END
      {
        "netflow": {
          "destinationTransportPort": 5355,
          "tcpControlBits": 0,
          "vmwareUnknown890": 1,
          "ingressInterface": 3,
          "ipClassOfService": 0,
          "version": 10,
          "packetDeltaCount": 2,
          "flowEndReason": 1,
          "sourceIPv6Address": "fe80::5187:5cd8:d750:cdc9",
          "protocolIdentifier": 17,
          "flowDirection": 1,
          "layer2SegmentId": 0,
          "egressInterface": 11,
          "octetDeltaCount": 144,
          "destinationIPv6Address": "ff02::1:3",
          "sourceTransportPort": 61329,
          "flowEndMilliseconds": "2016-12-22T12:25:49.000Z",
          "maximumTTL": 1,
          "vmwareUnknown888": 2,
          "flowStartMilliseconds": "2016-12-22T12:25:49.000Z",
          "vmwareUnknown889": 0
        },
        "@timestamp": "2016-12-22T12:26:04.000Z",
        "@version": "1"
      }
      END
      events.map{|event| event.gsub(/\s+/, "")}
    end

    it "should decode raw data" do
      expect(decode.size).to eq(5)
      expect(decode[4].get("[netflow][sourceIPv6Address]")).to eq("fe80::5187:5cd8:d750:cdc9")
      expect(decode[4].get("[netflow][destinationIPv6Address]")).to eq("ff02::1:3")
      expect(decode[4].get("[netflow][octetDeltaCount]")).to eq(144)
      expect(decode[4].get("[netflow][destinationTransportPort]")).to eq(5355)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end

  context "Juniper SRX options template with 0 scope field length" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_juniper_srx_tplopt.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "netflow": {
            "flow_seq_num": 338,
            "flowset_id": 256,
            "version":9,
            "sampling_algorithm":2,
            "sampling_interval":1
          },
          "@timestamp":"2016-11-29T00:21:56.000Z",
          "@version":"1"
        }
        END
      events.map{|event| event.gsub(/\s+/, "")}
    end

    it "should decode raw data" do
      expect(decode.size).to eq(1)
      expect(decode[0].get("[netflow][sampling_algorithm]")).to eq(2)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end

  context "Netflow 9 template with 0 length fields" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_0length_fields_tpl_data.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "netflow":{  
             "output_snmp":3,
             "dst_mask":32,
             "in_pkts":0,
             "ipv4_dst_addr":"239.255.255.250",
             "first_switched":"2016-12-23T01:34:52.999Z",
             "flowset_id":256,
             "l4_src_port":0,
             "src_mask":32,
             "version":9,
             "flow_seq_num":100728833,
             "ipv4_src_addr":"192.168.1.33",
             "in_bytes":0,
             "protocol":2,
             "input_snmp":2,
             "last_switched":"2016-12-23T01:34:52.999Z",
             "tcp_flags":0,
             "engine_id":1,
             "out_pkts":1,
             "out_bytes":32,
             "l4_dst_port":0,
             "direction":1
          },
          "@timestamp":"2016-12-23T01:35:31.000Z",
          "@version":"1"
        }
      END
      events.map{|event| event.gsub(/\s+/, "")}
    end

    it "should decode raw data" do
      expect(decode.size).to eq(10)
      expect(decode[9].get("[netflow][ipv4_src_addr]")).to eq("192.168.1.33")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[9].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end

end

describe LogStash::Codecs::Netflow, 'missing templates, no template caching configured' do
  subject do
    LogStash::Codecs::Netflow.new.tap do |codec|
      expect{codec.register}.not_to raise_error
    end
  end

  let(:logger) { double("logger") }

  before :each do
    allow(LogStash::Codecs::Netflow).to receive(:logger).and_return(logger)
    allow(logger).to receive(:debug) {}
    allow(logger).to receive(:warn) {}
  end

  let(:decode) do
    [].tap do |events|
      data.each { |packet| subject.decode(packet){|event| events << event}}
    end
  end

  context "IPFIX Netscaler with variable length fields, missing templates" do
    let(:data) do
      data = []
      data << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_netscaler_data.dat"), :mode => "rb")
    end

    it "can not / should not decode any data" do
      expect(decode.size).to eq(0)
      expect{decode[0].get("[netflow][version]")}.to raise_error(NoMethodError, /undefined method .get. for nil:NilClass/)
      expect{JSON.parse(decode[0].to_json)}.to raise_error(JSON::ParserError)
    end

    it "should report missing templates" do
      expect(logger).to receive(:warn).with(/No matching template for flow id/)
      decode[0]
    end
  end
end

# New subject with config, ordered testing since we need caching before data processing
describe LogStash::Codecs::Netflow, 'configured with template caching', :order => :defined do
  context "IPFIX Netscaler with variable length fields" do
    subject do
      LogStash::Codecs::Netflow.new(cache_config).tap do |codec|
        expect{codec.register}.not_to raise_error
      end
    end

    let(:tmp_dir) { ENV["TMP"] || ENV["TMPDIR"] || ENV["TEMP"] || "/tmp" }

    let(:cache_config) do
      { "cache_save_path" => tmp_dir }
    end

    let(:data) do
      # this ipfix raw data was produced by a Netscaler appliance and captured with wireshark
      # select packet bytes were then exported and sort of Pseudonymized to protect corp data
      data = []
      data << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_netscaler_data.dat"), :mode => "rb")
    end

    let(:templates) do
      templates = []
      templates << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_netscaler_tpl.dat"), :mode => "rb")
    end

    let(:cache) do
      [].tap do |events|
        templates.each { |packet| subject.decode(packet){|event| events << event}}
      end
    end

    let(:decode) do
      [].tap do |events|
        data.each { |packet| subject.decode(packet){|event| events << event}}
      end
    end

    let(:cached_templates) do
      cached_templates = <<-END
        {
          "0|256": [
            ["uint32","observationPointId"],["uint32","exportingProcessId"],["uint64","flowId"],["uint32","netscalerTransactionId"],["uint32","netscalerConnectionId"],
            ["uint8","ipVersion"],["uint8","protocolIdentifier"],["skip",null,{"length":2}],["ip4_addr","sourceIPv4Address"],["ip4_addr","destinationIPv4Address"],
            ["uint16","sourceTransportPort"],["uint16","destinationTransportPort"],["uint64","packetDeltaCount"],["uint64","octetDeltaCount"],["uint8","tcpControlBits"],
            ["uint64","netscalerFlowFlags"],["uint64","flowStartMicroseconds"],["uint64","flowEndMicroseconds"],["uint32","ingressInterface"],["uint32","egressInterface"],
            ["uint32","netscalerAppNameAppId"],["OctetArray","netscalerConnectionChainID",{"initial_length":16}],["uint8","netscalerConnectionChainHopCount"],["uint16","netscalerUnknown330"]],
          "0|257": [
            ["uint32","observationPointId"],["uint32","exportingProcessId"],["uint64","flowId"],["uint32","netscalerTransactionId"],["uint32","netscalerConnectionId"],
            ["uint8","ipVersion"],["uint8","protocolIdentifier"],["skip",null,{"length":2}],["ip4_addr","sourceIPv4Address"],["ip4_addr","destinationIPv4Address"],
            ["uint16","sourceTransportPort"],["uint16","destinationTransportPort"],["uint64","packetDeltaCount"],["uint64","octetDeltaCount"],["uint8","tcpControlBits"],
            ["uint64","netscalerFlowFlags"],["uint64","flowStartMicroseconds"],["uint64","flowEndMicroseconds"],["uint32","netscalerRoundTripTime"],["uint32","egressInterface"],
            ["uint32","ingressInterface"],["uint32","netscalerAppNameAppId"],["OctetArray","netscalerConnectionChainID",{"initial_length":16}],["uint8","netscalerConnectionChainHopCount"],
            ["uint16","netscalerUnknown329"],["uint16","netscalerUnknown331"],["uint32","netscalerUnknown332"]],
          "0|258": [
            ["uint32","observationPointId"],["uint32","exportingProcessId"],["uint64","flowId"],["uint32","netscalerTransactionId"],["uint32","netscalerConnectionId"],
            ["uint8","ipVersion"],["uint8","protocolIdentifier"],["skip",null,{"length":2}],["ip4_addr","sourceIPv4Address"],["ip4_addr","destinationIPv4Address"],
            ["uint16","sourceTransportPort"],["uint16","destinationTransportPort"],["uint64","packetDeltaCount"],["uint64","octetDeltaCount"],["uint8","tcpControlBits"],
            ["uint64","netscalerFlowFlags"],["uint64","flowStartMicroseconds"],["uint64","flowEndMicroseconds"],["uint32","ingressInterface"],["uint32","egressInterface"],
            ["uint32","netscalerAppNameAppId"],["uint32","netscalerAppUnitNameAppId"],["uint64","netscalerHttpResForwFB"],["uint64","netscalerHttpResForwLB"],
            ["OctetArray","netscalerConnectionChainID",{"initial_length":16}],["uint8","netscalerConnectionChainHopCount"],["uint16","netscalerUnknown330"],
            ["VarString","netscalerAaaUsername"],["VarString","netscalerHttpReqUrl"],["VarString","netscalerHttpReqCookie"],["VarString","netscalerHttpReqReferer"],
            ["VarString","netscalerHttpReqMethod"],["VarString","netscalerHttpReqHost"],["VarString","netscalerHttpReqUserAgent"],["VarString","netscalerHttpContentType"],
            ["VarString","netscalerHttpReqAuthorization"],["VarString","netscalerHttpReqVia"],["VarString","netscalerHttpReqXForwardedFor"],["VarString","netscalerHttpDomainName"]],
          "0|259": [
            ["uint32","observationPointId"],["uint32","exportingProcessId"],["uint64","flowId"],["uint32","netscalerTransactionId"],["uint32","netscalerConnectionId"],
            ["uint8","ipVersion"],["uint8","protocolIdentifier"],["skip",null,{"length":2}],["ip6_addr","sourceIPv6Address"],["ip6_addr","destinationIPv6Address"],
            ["uint16","sourceTransportPort"],["uint16","destinationTransportPort"],["uint64","packetDeltaCount"],["uint64","octetDeltaCount"],["uint8","tcpControlBits"],
            ["uint64","netscalerFlowFlags"],["uint64","flowStartMicroseconds"],["uint64","flowEndMicroseconds"],["uint32","ingressInterface"],["uint32","egressInterface"],
            ["uint32","netscalerAppNameAppId"],["OctetArray","netscalerConnectionChainID",{"initial_length":16}],["uint8","netscalerConnectionChainHopCount"],["uint16","netscalerUnknown330"]],
          "0|260": [
            ["uint32","observationPointId"],["uint32","exportingProcessId"],["uint64","flowId"],["uint32","netscalerTransactionId"],["uint32","netscalerConnectionId"],
            ["uint8","ipVersion"],["uint8","protocolIdentifier"],["skip",null,{"length":2}],["ip6_addr","sourceIPv6Address"],["ip6_addr","destinationIPv6Address"],
            ["uint16","sourceTransportPort"],["uint16","destinationTransportPort"],["uint64","packetDeltaCount"],["uint64","octetDeltaCount"],["uint8","tcpControlBits"],
            ["uint64","netscalerFlowFlags"],["uint64","flowStartMicroseconds"],["uint64","flowEndMicroseconds"],["uint32","netscalerRoundTripTime"],["uint32","egressInterface"],
            ["uint32","ingressInterface"],["uint32","netscalerAppNameAppId"],["OctetArray","netscalerConnectionChainID",{"initial_length":16}],["uint8","netscalerConnectionChainHopCount"],
            ["uint16","netscalerUnknown329"],["uint16","netscalerUnknown331"],["uint32","netscalerUnknown332"]],
          "0|261": [
            ["uint32","observationPointId"],["uint32","exportingProcessId"],["uint64","flowId"],["uint32","netscalerTransactionId"],["uint32","netscalerConnectionId"],
            ["uint8","ipVersion"],["uint8","protocolIdentifier"],["skip",null,{"length":2}],["ip6_addr","sourceIPv6Address"],["ip6_addr","destinationIPv6Address"],
            ["uint16","sourceTransportPort"],["uint16","destinationTransportPort"],["uint64","packetDeltaCount"],["uint64","octetDeltaCount"],["uint8","tcpControlBits"],
            ["uint64","netscalerFlowFlags"],["uint64","flowStartMicroseconds"],["uint64","flowEndMicroseconds"],["uint32","ingressInterface"],["uint32","egressInterface"],
            ["uint32","netscalerAppNameAppId"],["uint32","netscalerAppUnitNameAppId"],["uint64","netscalerHttpResForwFB"],["uint64","netscalerHttpResForwLB"],
            ["OctetArray","netscalerConnectionChainID",{"initial_length":16}],["uint8","netscalerConnectionChainHopCount"],["uint16","netscalerUnknown330"],
            ["uint32","netscalerCacheRedirClientConnectionCoreID"],["uint32","netscalerCacheRedirClientConnectionTransactionID"],["VarString","netscalerAaaUsername"],
            ["VarString","netscalerHttpReqUrl"],["VarString","netscalerHttpReqCookie"],["VarString","netscalerHttpReqReferer"],["VarString","netscalerHttpReqMethod"],
            ["VarString","netscalerHttpReqHost"],["VarString","netscalerHttpReqUserAgent"],["VarString","netscalerHttpContentType"],["VarString","netscalerHttpReqAuthorization"],
            ["VarString","netscalerHttpReqVia"],["VarString","netscalerHttpReqXForwardedFor"],["VarString","netscalerHttpDomainName"]],
          "0|262": [
            ["uint32","observationPointId"],["uint32","exportingProcessId"],["uint64","flowId"],["uint32","netscalerTransactionId"],["uint32","netscalerConnectionId"],
            ["uint8","ipVersion"],["uint8","protocolIdentifier"],["skip",null,{"length":2}],["ip4_addr","sourceIPv4Address"],["ip4_addr","destinationIPv4Address"],
            ["uint16","sourceTransportPort"],["uint16","destinationTransportPort"],["uint64","packetDeltaCount"],["uint64","octetDeltaCount"],["uint8","tcpControlBits"],
            ["uint64","netscalerFlowFlags"],["uint64","flowStartMicroseconds"],["uint64","flowEndMicroseconds"],["uint32","ingressInterface"],["uint32","egressInterface"],
            ["uint16","netscalerHttpRspStatus"],["uint64","netscalerHttpRspLen"],["uint64","netscalerServerTTFB"],["uint64","netscalerServerTTLB"],
            ["uint32","netscalerAppNameAppId"],["uint32","netscalerMainPageId"],["uint32","netscalerMainPageCoreId"],["uint64","netscalerHttpReqRcvFB"],
            ["uint64","netscalerHttpReqForwFB"],["uint64","netscalerHttpResRcvFB"],["uint64","netscalerHttpReqRcvLB"],["uint64","netscalerHttpReqForwLB"],
            ["uint64","netscalerHttpResRcvLB"],["uint32","netscalerClientRTT"],["uint16","netscalerUnknown330"],["uint32","netscalerUnknown347"],["VarString","netscalerAaaUsername"],
            ["VarString","netscalerHttpContentType"],["VarString","netscalerHttpResLocation"],["VarString","netscalerHttpResSetCookie"],["VarString","netscalerHttpResSetCookie2"]]
        }
        END
    end

    it "should cache templates" do
      expect(cache.size).to eq(0)
      expect(JSON.parse(File.read("#{tmp_dir}/ipfix_templates.cache"))).to eq(JSON.parse(cached_templates))
    end

    it "should decode raw data based on cached templates" do
      expect(decode.size).to eq(3)
      expect(decode[0].get("[netflow][version]")).to eq(10)
      expect(decode[0].get("[netflow][flowEndMicroseconds]")).to eq('2016-11-11T12:09:19.000Z')
      expect(decode[0].get("[netflow][netscalerConnectionId]")).to eq(14460661)
      expect(decode[1].get("[netflow][version]")).to eq(10)
      expect(decode[1].get("[netflow][observationPointId]")).to eq(167954698)
      expect(decode[1].get("[netflow][netscalerFlowFlags]")).to eq(1157636096)
      expect(decode[2].get("[netflow][version]")).to eq(10)
      expect(decode[2].get("[netflow][netscalerAppUnitNameAppId]")).to eq(239927296)
      expect(decode[2].get("[netflow][netscalerHttpReqXForwardedFor]")).to eq('11.222.33.255')
      FileUtils.rm_rf(tmp_dir)
    end
  end
end

describe LogStash::Codecs::Netflow, 'configured with include_flowset_id for ipfix' do
  subject do
    LogStash::Codecs::Netflow.new(include_flowset_id_config).tap do |codec|
      expect{codec.register}.not_to raise_error
    end
  end

  let(:include_flowset_id_config) do
    { "include_flowset_id" => true }
  end

  let(:decode) do
    [].tap do |events|
      data.each { |packet| subject.decode(packet){|event| events << event}}
    end
  end

  let(:data) do
    # this ipfix raw data was produced by a Netscaler appliance and captured with wireshark
    # select packet bytes were then exported and sort of Pseudonymized to protect corp data
    data = []
    data << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_netscaler_tpl.dat"), :mode => "rb")
    data << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_netscaler_data.dat"), :mode => "rb")
  end

  it "should decode raw data" do
    expect(decode.size).to eq(3)
    expect(decode[0].get("[netflow][version]")).to eq(10)
    expect(decode[0].get("[netflow][flowEndMicroseconds]")).to eq('2016-11-11T12:09:19.000Z')
    expect(decode[0].get("[netflow][netscalerConnectionId]")).to eq(14460661)
    expect(decode[1].get("[netflow][version]")).to eq(10)
    expect(decode[1].get("[netflow][observationPointId]")).to eq(167954698)
    expect(decode[1].get("[netflow][netscalerFlowFlags]")).to eq(1157636096)
    expect(decode[2].get("[netflow][version]")).to eq(10)
    expect(decode[2].get("[netflow][netscalerAppUnitNameAppId]")).to eq(239927296)
  end

  it "should include flowset_id" do
    expect(decode[0].get("[netflow][flowset_id]")).to eq(258)
    expect(decode[1].get("[netflow][flowset_id]")).to eq(257)
    expect(decode[2].get("[netflow][flowset_id]")).to eq(258)
  end


end
