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
end
