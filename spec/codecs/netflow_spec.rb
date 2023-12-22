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

  let(:is_LS_8) do
    logstash_version = Gem::Version.create(LOGSTASH_CORE_VERSION)
    Gem::Requirement.create('>= 8.0').satisfied_by?(logstash_version)
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

    let(:micros) { is_LS_8 ? "328" : "" }

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@timestamp": "2015-05-02T18:38:08.280#{micros}Z",
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
            "first_switched": "2015-06-21T11:40:52.194#{micros}Z",
            "last_switched": "2015-05-02T18:38:08.476#{micros}Z",
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
          "@timestamp": "2015-05-02T18:38:08.280#{micros}Z",
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
            "first_switched": "2015-06-21T11:40:52.194#{micros}Z",
            "last_switched": "2015-05-02T18:38:08.476#{micros}Z",
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
            "last_switched":"2015-10-08T19:03:47.141Z",
            "first_switched":"2015-10-08T19:03:47.140Z",
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

    end

    it "should decode the mac address" do
      expect(decode[1].get("[netflow][in_src_mac]")).to eq("00:50:56:c0:00:01")
      expect(decode[1].get("[netflow][in_dst_mac]")).to eq("00:0c:29:70:86:09")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[1].to_json)).to eq(JSON.parse(json_events[0]))
    end
  end

  context "Netflow 9 Cisco ACI" do
    let(:data) do
      data = []
      data << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_cisco_aci_tpl256-258.dat"), :mode => "rb")
      data << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_cisco_aci_data256.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
      {
        "@timestamp": "2018-10-15T11:29:00.000Z",
        "netflow": {
          "version": 9,
          "l4_dst_port": 49411,
          "flowset_id": 256,
          "l4_src_port": 179,
          "ipv4_dst_addr": "10.154.231.146",
          "in_pkts": 2,
          "first_switched": "2018-10-15T11:28:05.019Z",
          "protocol": 6,
          "last_switched": "2018-10-15T11:28:24.066Z",
          "ip_protocol_version": 4,
          "in_bytes": 99,
          "flow_seq_num": 36,
          "tcp_flags": 24,
          "input_snmp": 369139712,
          "ipv4_src_addr": "10.154.231.145",
          "src_vlan": 0,
          "direction": 0
        },
        "@version": "1"
      }
      END

    end

    it "should decode the mac address" do
      expect(decode.size).to eq(3)
      expect(decode[0].get("[netflow][ipv4_src_addr]")).to eq("10.154.231.145")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
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

    end

    it "should decode raw data" do
      expect(decode.size).to eq(14)
      expect(decode[1].get("[netflow][version]")).to eq(9)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[1].to_json)).to eq(JSON.parse(json_events[0]))
    end
  end

  context "Netflow 9 multiple netflow exporters" do
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
            "last_switched":"2015-10-08T19:03:47.141Z",
            "first_switched":"2015-10-08T19:03:47.140Z",
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
            "last_switched":"2015-10-08T19:05:56.015Z",
            "first_switched":"2015-10-08T19:05:56.010Z"
          },
          "@version":"1"
        }
      END

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

  context "Netflow5 mikrotik" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow5_test_microtik.dat"), :mode => "rb")
    end

    let(:micros) { is_LS_8 ? "932" : "" }

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@timestamp": "2016-07-21T13:51:57.514#{micros}Z",
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
            "first_switched": "2016-07-21T13:51:42.254#{micros}Z",
            "last_switched": "2016-07-21T13:51:42.254#{micros}Z",
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
            "first_switched": "2016-07-21T13:52:34.936Z",
            "last_switched": "2016-07-21T13:52:34.936Z",
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

  context "Netflow 9 ipt_netflow reduced size encoding" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_iptnetflow_reduced_size_encoding_tpldata260.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
      {
        "netflow": {
          "l4_src_port": 443,
          "last_switched": "2018-02-18T05:46:54.992Z",
          "ingressPhysicalInterface": 7,
          "in_bytes": 187,
          "tcpOptions": 2164260864,
          "in_dst_mac": "00:1b:21:bc:24:dd",
          "protocol": 6,
          "output_snmp": 8,
          "ethernetType": 2048,
          "src_tos": 0,
          "l4_dst_port": 38164,
          "input_snmp": 7,
          "version": 9,
          "in_pkts": 3,
          "flow_seq_num": 344481,
          "ipv4_next_hop": "10.232.5.1",
          "flowset_id": 260,
          "first_switched": "2018-02-18T05:46:54.800Z",
          "tcp_flags": 25,
          "ipv4_dst_addr": "10.233.150.21",
          "ipv4_src_addr": "2.17.140.47",
          "in_src_mac": "90:e2:ba:23:09:fc",
          "egressPhysicalInterface": 8
        },
        "@timestamp": "2018-02-18T05:47:09.000Z",
        "@version": "1"
      }
      END

    end

    it "should decode raw data" do
      expect(decode.size).to eq(12)
      expect(decode[11].get("[netflow][in_dst_mac]")).to eq("00:1b:21:bc:24:dd")
      expect(decode[11].get("[netflow][ipv4_src_addr]")).to eq("2.17.140.47")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[11].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end

  context "Netflow 9 H3C" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_h3c_tpl3281.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_h3c_data3281.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
      {
        "netflow": {
          "in_pkts": 9,
          "src_as": 0,
          "flowset_id": 3281,
          "l4_dst_port": 0,
          "last_switched": "2018-05-21T09:25:04.928Z",
          "dst_mask": 24,
          "tcp_flags": 0,
          "src_tos": 0,
          "dst_as": 0,
          "input_snmp": 2662,
          "direction": 0,
          "version": 9,
          "src_mask": 24,
          "sampling_algorithm": 0,
          "sampling_interval": 0,
          "flow_seq_num": 60342277,
          "src_traffic_index": 0,
          "in_bytes": 5092,
          "ipv4_src_addr": "10.22.166.36",
          "first_switched": "2018-05-21T09:24:04.922Z",
          "ipv4_dst_addr": "10.21.75.38",
          "ipv4_next_hop": "10.21.17.78",
          "forwarding_status": {
            "status": 0,
            "reason": 0
          },
          "l4_src_port": 0,
          "protocol": 6,
          "output_snmp": 1743,
          "dst_traffic_index": 4294967295,
          "ip_protocol_version": 4
        },
        "@version": "1",
        "@timestamp": "2018-05-21T09:25:04.000Z"
      }
      END

    end

    it "should decode raw data" do
      expect(decode.size).to eq(16)
      expect(decode[11].get("[netflow][dst_traffic_index]")).to eq(4294967295)
      expect(decode[11].get("[netflow][src_traffic_index]")).to eq(0)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[15].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end

  context "Netflow 9 IE150 IE151" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_unknown_tpl266_292_data.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
      {
        "@version": "1",
        "netflow": {
          "in_pkts": 1,
          "ipv4_dst_addr": "192.168.0.2",
          "src_tos": 0,
          "flowset_id": 266,
          "l4_src_port": 137,
          "version": 9,
          "flow_seq_num": 35088,
          "ipv4_src_addr": "192.168.0.3",
          "protocol": 17,
          "in_bytes": 78,
          "egressVRFID": 0,
          "input_snmp": 13,
          "flow_sampler_id": 1,
          "ingressVRFID": 0,
          "flowEndSeconds": 1512147866,
          "l4_dst_port": 137,
          "flowStartSeconds": 1512147866,
          "direction": 0
        },
        "@timestamp": "2017-12-01T17:04:39.000Z"
      }
      END

      events << <<-END
      {
        "@version": "1",
        "netflow": {
          "output_snmp": 13,
          "in_pkts": 1,
          "ipv4_dst_addr": "192.168.0.5",
          "src_tos": 0,
          "flowset_id": 292,
          "l4_src_port": 58130,
          "version": 9,
          "flow_seq_num": 35088,
          "ipv4_src_addr": "192.168.0.4",
          "protocol": 17,
          "in_bytes": 232,
          "egressVRFID": 0,
          "flow_sampler_id": 1,
          "ingressVRFID": 0,
          "flowEndSeconds": 1512147869,
          "l4_dst_port": 6343,
          "flowStartSeconds": 1512147869,
          "direction": 1
        },
        "@timestamp": "2017-12-01T17:04:39.000Z"
      }
      END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(2)
      expect(decode[1].get("[netflow][flowStartSeconds]")).to eq(1512147869)
      expect(decode[1].get("[netflow][flowEndSeconds]")).to eq(1512147869)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
      expect(JSON.parse(decode[1].to_json)).to eq(JSON.parse(json_events[1]))
    end

  end

  context "Netflow 9 Palo Alto 1 flowset in large zero filled packet" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_paloalto_81_tpl256-263.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_paloalto_81_data257_1flowset_in_large_zerofilled_packet.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
      {
        "netflow": {
          "output_snmp":500010002,
          "icmp_type":0,
          "in_pkts":3,
          "src_tos":0,
          "ipv4_dst_addr":"134.220.1.156",
          "first_switched":"2018-06-06T13:20:03.000Z",
          "flowset_id":257,
          "l4_src_port":88,
          "fw_event":2,
          "version":9,
          "flow_seq_num":970830115,
          "ipv4_src_addr":"134.220.2.6",
          "in_bytes":363,
          "protocol":6,
          "tcp_flags":94,
          "input_snmp":500010024,
          "last_switched":"2018-06-06T13:20:03.000Z",
          "user_id":"unknown",
          "conn_id":1428388,
          "privateEnterpriseNumber":25461,
          "l4_dst_port":50234,
          "app_id":"kerberos",
          "direction":0
        },
        "@timestamp":"2018-06-06T13:20:17.000Z",
        "@version":"1"
      }
      END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(1)
      expect(decode[0].get("[netflow][app_id]")).to eq("kerberos")
      expect(decode[0].get("[netflow][ipv4_src_addr]")).to eq("134.220.2.6")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end

  context "Netflow 9 H3C Netstream with varstring" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_h3c_netstream_varstring_tpl3281.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_h3c_netstream_varstring_data3281.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
      {
        "@version": "1",
        "@timestamp": "2018-07-18T01:35:35.000Z",
        "netflow": {
          "in_pkts": 9,
          "last_switched": "2018-07-18T01:35:03.969Z",
          "direction": 0,
          "first_switched": "2018-07-18T01:34:34.274Z",
          "ipv4_dst_addr": "20.20.255.255",
          "src_tos": 0,
          "ipv4_src_addr": "20.20.20.20",
          "output_snmp": 0,
          "protocol": 17,
          "l4_src_port": 137,
          "ipv4_next_hop": "0.0.0.0",
          "flowset_id": 3281,
          "l4_dst_port": 137,
          "input_snmp": 17,
          "ip_protocol_version": 4,
          "version": 9,
          "sampling_algorithm": 0,
          "forwarding_status": {
            "status": 0,
            "reason": 0
          },
          "tcp_flags": 0,
          "sampling_interval": 0,
          "flow_seq_num": 133,
          "dst_traffic_index": 4294967295,
          "src_mask": 32,
          "src_as": 0,
          "dst_as": 0,
          "dst_mask": 32,
          "VRFname": "",
          "in_bytes": 702,
          "src_traffic_index": 0
        }
      }
      END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(1)
      expect(decode[0].get("[netflow][VRFname]")).to eq("")
      expect(decode[0].get("[netflow][l4_src_port]")).to eq(137)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end


  context "Netflow 9 Fortigate FortiOS 54x appid" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_fortigate_fortios_542_appid_tpl258-269.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_fortigate_fortios_542_appid_data258_262.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
      {
        "netflow": {
          "output_snmp": 2,
          "forwarding_status": {
            "reason": 0,
            "status": 1
          },
          "xlate_src_port": 45380,
          "in_pkts": 6,
          "ipv4_dst_addr": "182.50.136.239",
          "first_switched": "2018-05-11T00:54:10.580Z",
          "flowset_id": 262,
          "l4_src_port": 45380,
          "xlate_dst_port": 0,
          "version": 9,
          "application_id": "20..12356..36660",
          "flow_seq_num": 350,
          "ipv4_src_addr": "192.168.100.151",
          "in_bytes": 748,
          "protocol": 6,
          "flow_end_reason": 3,
          "last_switched": "2018-05-11T00:54:10.990Z",
          "input_snmp": 8,
          "out_pkts": 6,
          "out_bytes": 748,
          "xlate_src_addr_ipv4": "10.0.0.250",
          "xlate_dst_addr_ipv4": "0.0.0.0",
          "l4_dst_port": 80
        },
        "@timestamp": "2018-05-11T00:54:11.000Z",
        "@version": "1"
      }
      END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(17)
      expect(decode[1].get("[netflow][application_id]")).to eq("20..12356..40568")
      expect(decode[2].get("[netflow][application_id]")).to eq("20..12356..40568")
      expect(decode[16].get("[netflow][application_id]")).to eq("20..12356..0")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end


  context "IPFIX from IXIA something something" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_ixia_tpldata256.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
      {
        "@timestamp": "2018-10-25T12:24:43.000Z",
        "netflow": {
          "icmpTypeCodeIPv4": 0,
          "ixiaDstLongitude": 100.33540344238281,
          "ixiaHttpUserAgent": "",
          "ixiaDeviceName": "unknown",
          "flowStartMilliseconds": "2018-10-25T12:24:19.882Z",
          "destinationIPv4Address": "202.170.60.247",
          "ixiaDeviceId": 0,
          "ixiaL7AppName": "unknown",
          "ixiaBrowserId": 0,
          "ixiaDstLatitude": 5.411200046539307,
          "sourceIPv4Address": "119.103.128.175",
          "ixiaSrcAsName": "CHINANET-BACKBONE No.31,Jin-rong Street, CN",
          "ixiaThreatIPv4": "0.0.0.0",
          "ixiaHttpHostName": "",
          "sourceTransportPort": 51695,
          "tcpControlBits": 0,
          "egressInterface": 1,
          "flowEndReason": 1,
          "ixiaSrcLongitude": 114.27339935302734,
          "version": 10,
          "packetDeltaCount": 4,
          "destinationTransportPort": 36197,
          "ixiaRevPacketDeltaCount": 0,
          "reverseIcmpTypeCodeIPv4": 0,
          "ixiaRevOctetDeltaCount": 0,
          "ixiaThreatType": "",
          "ixiaHttpUri": "",
          "octetDeltaCount": 360,
          "ixiaBrowserName": "-",
          "protocolIdentifier": 17,
          "bgpSourceAsNumber": 4134,
          "bgpDestinationAsNumber": 24090,
          "ixiaDstAsName": "UNISAINS-AS-AP Universiti Sains Malaysia (USM), MY",
          "ixiaLatency": 0,
          "ixiaSrcLatitude": 30.58009910583496,
          "ixiaL7AppId": 0,
          "ingressInterface": 1,
          "flowEndMilliseconds": "2018-10-25T12:24:32.022Z"
        },
        "@version": "1"
      }
      END

    end

    it "should decode raw data" do
      expect(decode.size).to eq(1)
      expect(decode[0].get("[netflow][ixiaDstAsName]")).to eq("UNISAINS-AS-AP Universiti Sains Malaysia (USM), MY")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end

  context "IPFIX options template from Juniper MX240 JunOS 15.1 R6 S3" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_juniper_mx240_junos151r6s3_opttpl512.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_juniper_mx240_junos151r6s3_data512.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
      {
        "@timestamp": "2018-06-01T15:11:53.000Z",
        "@version": "1",
        "netflow": {
          "exportProtocolVersion": 10,
          "exportingProcessId": 2,
          "flowActiveTimeout": 60,
          "exportTransportProtocol": 17,
          "flowIdleTimeout": 60,
          "exportedFlowRecordTotalCount": 76,
          "exportedMessageTotalCount": 76,
          "samplingInterval": 1000,
          "exporterIPv6Address": "::",
          "systemInitTimeMilliseconds": 1262761598000,
          "version": 10,
          "exporterIPv4Address": "10.0.0.1"
        }
      }
      END

    end

    it "should decode raw data" do
      expect(decode.size).to eq(1)
      expect(decode[0].get("[netflow][exporterIPv4Address]")).to eq("10.0.0.1")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end


  context "IPFIX Nokia BRAS" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_nokia_bras_tpl.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_nokia_bras_data256.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@version": "1",
          "netflow": {
            "destinationIPv4Address": "10.0.0.34",
            "destinationTransportPort": 80,
            "protocolIdentifier": 6,
            "sourceIPv4Address": "10.0.1.228",
            "natSubString": "USER1@10.10.0.123",
            "sourceTransportPort": 5878,
            "version": 10,
            "flowId": 3389049088,
            "natOutsideSvcid": 0,
            "flowStartMilliseconds": "2017-12-14T07:23:45.148Z",
            "natInsideSvcid": 100
          },
          "@timestamp": "2017-12-14T07:23:45.000Z"
        }
      END

    end

    it "should decode raw data" do
      expect(decode.size).to eq(1)
      expect(decode[0].get("[netflow][natInsideSvcid]")).to eq(100)
      expect(decode[0].get("[netflow][natOutsideSvcid]")).to eq(0)
      expect(decode[0].get("[netflow][natSubString]")).to eq("USER1@10.10.0.123")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end

  context "IPFIX Procera" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_procera_tpl52935.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_procera_data52935.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@timestamp": "2018-04-15T03:30:00.000Z",
          "@version": "1",
          "netflow": {
            "proceraFlowBehavior": "INTERACTIVE,CLIENT_IS_LOCAL,INBOUND,ESTABLISHED,ACTIVE",
            "sourceIPv6Address": "::",
            "proceraOutgoingOctets": 3310,
            "sourceTransportPort": 33689,
            "destinationIPv6Address": "::",
            "destinationTransportPort": 179,
            "flowStartSeconds": "2018-04-15T03:25:00.000Z",
            "proceraHttpContentType": "",
            "proceraContentCategories": "",
            "proceraSubscriberIdentifier": "",
            "proceraTemplateName": "IPFIX",
            "proceraHttpLocation": "",
            "protocolIdentifier": 6,
            "sourceIPv4Address": "138.44.161.14",
            "flowEndSeconds": "2018-04-15T03:30:00.000Z",
            "version": 10,
            "proceraBaseService": "BGP-4",
            "bgpSourceAsNumber": 7575,
            "proceraIncomingOctets": 7076,
            "bgpDestinationAsNumber": 7575,
            "proceraHttpUrl": "",
            "proceraService": "BGP-4",
            "proceraHttpFileLength": 0,
            "destinationIPv4Address": "138.44.161.13"
          }
        }
      END

    end

    it "should decode raw data" do
      expect(decode.size).to eq(8)
      expect(decode[7].get("[netflow][sourceIPv4Address]")).to eq("138.44.161.14")
      expect(decode[7].get("[netflow][proceraBaseService]")).to eq("BGP-4")
      expect(decode[7].get("[netflow][proceraFlowBehavior]")).to eq("INTERACTIVE,CLIENT_IS_LOCAL,INBOUND,ESTABLISHED,ACTIVE")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[7].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end

  context "IPFIX Barracuda extended uniflow template 256" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_barracuda_extended_uniflow_tpl256.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_barracuda_extended_uniflow_data256.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
      {
        "netflow": {
        "FW_Rule": "MTH:MTH-MC-to-Inet",
        "AuditCounter": 4157725,
        "sourceIPv4Address": "64.235.151.76",
        "version": 10,
        "sourceTransportPort": 443,
        "sourceMacAddress": "00:00:00:00:00:00",
        "ingressInterface": 3689,
        "flowEndSysUpTime": 1957197969,
        "octetTotalCount": 0,
        "ConnTransportPort": 443,
        "ConnIPv4Address": "64.235.151.76",
        "firewallEvent": 1,
        "protocolIdentifier": 6,
        "flowStartSysUpTime": 1957197969,
        "TrafficType": 0,
        "destinationTransportPort": 51917,
        "packetTotalCount": 0,
        "BindIPv4Address": "213.208.150.99",
        "Timestamp": 1524039407,
        "flowDurationMilliseconds": 0,
        "ServiceName": "https",
        "BindTransportPort": 64238,
        "octetDeltaCount": 0,
        "packetDeltaCount": 0,
        "destinationIPv4Address": "10.236.5.4",
        "LogOp": 1,
        "Reason": 0,
        "egressInterface": 35233,
        "ReasonText": "Normal Operation"
        },
        "@version": "1",
        "@timestamp": "2018-04-18T08:16:47.000Z"
      } 
      END

    end

    it "should decode raw data" do
      expect(decode.size).to eq(2)
      expect(decode[1].get("[netflow][FW_Rule]")).to eq("MTH:MTH-MC-to-Inet")
      expect(decode[1].get("[netflow][ReasonText]")).to eq("Normal Operation")
      expect(decode[1].get("[netflow][BindIPv4Address]")).to eq("213.208.150.99")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[1].to_json)).to eq(JSON.parse(json_events[0]))
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
            "first_switched": "2016-09-10T15:02:54.375Z", 
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
            "last_switched": "2016-09-10T15:23:45.363Z", 
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

  context "Netflow 9 nprobe DPI L7" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_nprobe_dpi.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "netflow": {
            "nprobe_proto": 82,
            "in_pkts": 1,
            "ipv4_dst_addr": "0.0.0.0",
            "first_switched": "1970-01-01T00:08:33.000Z",
            "flowset_id": 256,
            "l4_src_port": 0,
            "nprobe_proto_name": "\u0000\u00c1\u0000\u0000\u0001\u00ac\u0010\u0000d\u00e4O\u00ef\u00ff\u00ff\u00fa\u0007",
            "version": 9,
            "application_id": "0..82",
            "flow_seq_num": 2,
            "ipv4_src_addr": "0.0.0.0",
            "protocol": 0,
            "in_bytes": 82,
            "application_name": "\u0000\u0000\u0000\u0000\u0000\"\u0000\u0000\u0000\u0000\u0004",
            "last_switched": "1970-01-01T00:08:36.000Z",
            "l4_dst_port": 0
          },
          "@timestamp": "1970-01-01T00:08:22.000Z",
          "@version": "1",
          "host": "172.16.32.201"
        }
        END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(1)
      expect(decode[0].get("[netflow][nprobe_proto]")).to eq(82)
      expect(decode[0].get("[netflow][application_id]")).to eq("0..82")
      expect(decode[0].get("[netflow][in_bytes]")).to eq(82)
    end

    it "should serialize to json" do
      # We skip this due to unprintable characters in the proto_name and application_name
      # expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
    end
  end

  context "Netflow 9 Fortigate FortiOS 5.2.1" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_fortigate_fortios_521_tpl.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_fortigate_fortios_521_data256.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_fortigate_fortios_521_data257.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "netflow": {
            "flow_seq_num": 13641,
            "scope_system": 1,
            "total_bytes_exp": 6871319015,
            "total_flows_exp": 107864,
            "flow_active_timeout": 1800,
            "flow_inactive_timeout": 15,
            "flowset_id": 256,
            "total_pkts_exp": 11920854,
            "version": 9,
            "sampling_algorithm": 1,
            "sampling_interval": 1
          },
          "@timestamp": "2017-07-18T05:42:14.000Z",
          "@version": "1"
        }
        END

      events << <<-END
        {
          "netflow": {
            "output_snmp": 3,
            "in_pkts": 3,
            "ipv4_dst_addr": "31.13.87.36",
            "first_switched": "2017-07-25T04:44:29.522Z",
            "flowset_id": 257,
            "l4_src_port": 61910,
            "version": 9,
            "flow_seq_num": 13635,
            "ipv4_src_addr": "192.168.99.7",
            "in_bytes": 152,
            "protocol": 6,
            "last_switched": "2017-07-25T04:44:38.522Z",
            "input_snmp": 9,
            "out_pkts": 0,
            "out_bytes": 0,
            "l4_dst_port": 443
          },
          "@timestamp": "2017-07-18T05:41:59.000Z",
          "@version": "1"
        }
        END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(2)
      expect(decode[0].get("[netflow][total_bytes_exp]")).to eq(6871319015)
      expect(decode[1].get("[netflow][ipv4_src_addr]")).to eq("192.168.99.7")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
      expect(JSON.parse(decode[1].to_json)).to eq(JSON.parse(json_events[1]))
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
            "first_switched": "2017-01-11T11:47:23.867Z",
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
            "last_switched": "2017-01-11T11:47:29.879Z",
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
            "first_switched": "2017-01-11T11:22:44.939Z",
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
            "last_switched": "2017-01-11T11:23:35.954Z",
            "streamcore_url": "\/mux.json",
            "streamcore_wan_rtt": 0,
            "streamcore_total_app_resp_time": 19
          },
          "@timestamp": "2017-01-11T11:23:51.000Z",
          "@version": "1"
        }
      END

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

  context "IPFIX Mikrotik RouterOS 6.39.2" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_mikrotik_tpl.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_mikrotik_data258.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_mikrotik_data259.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
      {
        "netflow": {
          "destinationIPv4Address": "192.168.128.17",
          "destinationTransportPort": 123,
          "flowStartSysUpTime": 2666794170,
          "tcpControlBits": 0,
          "postNATDestinationIPv4Address": "192.168.128.17",
          "flowEndSysUpTime": 2666794170,
          "sourceIPv4Address": "10.10.8.197",
          "ingressInterface": 13,
          "version": 10,
          "packetDeltaCount": 2,
          "ipVersion": 4,
          "protocolIdentifier": 17,
          "postNATSourceIPv4Address": "192.168.230.216",
          "egressInterface": 7,
          "octetDeltaCount": 152,
          "ipNextHopIPv4Address": "192.168.224.1",
          "sourceTransportPort": 123
        },
        "@timestamp": "2017-07-19T16:18:08.000Z",
        "@version": "1"
      }
      END

      events << <<-END
      {
        "netflow": {
          "destinationTransportPort": 5678,
          "ipNextHopIPv6Address": "ff02::1",
          "flowStartSysUpTime": 2666795750,
          "tcpControlBits": 0,
          "flowEndSysUpTime": 2666795750,
          "ingressInterface": 17,
          "version": 10,
          "packetDeltaCount": 2,
          "sourceIPv6Address": "fe80::ff:fe00:1201",
          "ipVersion": 6,
          "protocolIdentifier": 17,
          "egressInterface": 0,
          "octetDeltaCount": 370,
          "sourceTransportPort": 5678,
          "destinationIPv6Address": "fe80::ff:fe00:1201"
        },
        "@timestamp": "2017-07-19T16:18:08.000Z",
        "@version": "1"
      }
      END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(46)
      expect(decode[0].get("[netflow][postNATDestinationIPv4Address]")).to eq("192.168.128.17")
      expect(decode[45].get("[netflow][ipNextHopIPv6Address]")).to eq("ff02::1")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
      expect(JSON.parse(decode[45].to_json)).to eq(JSON.parse(json_events[1]))
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

    # in LS 8 the precision is up to nanos in LS 7 is up to millis
    let(:nanos) { is_LS_8 ? "128468" : "" }

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@timestamp": "2016-11-11T12:09:19.000Z",
          "netflow": {
            "netscalerHttpReqUserAgent": "Mozilla/5.0 (Commodore 64;  kobo.com) Gecko/20100101 Firefox/75.0",
            "destinationTransportPort": 443,
            "netscalerHttpReqCookie": "beer=123456789abcdefghijklmnopqrstuvw; AnotherCookie=1234567890abcdefghijklmnopqr; Shameless.Plug=Thankyou.Rakuten.Kobo.Inc.For.Allowing.me.time.to.work.on.this.and.contribute.back.to.the.community; Padding=aaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbccccccccccccccddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeffffffffffffffffffffffgggggggggggggggggggggggghhhhhhhhhhhhhhhhhiiiiiiiiiiiiiiiiiiiiiijjjjjjjjjjjjjjjjjjjjjjjjkkkkkkkkkkkkkkkkkklllllllllllllllmmmmmmmmmm; more=less; GJquote=There.is.no.spoon; GarrySays=Nice!!; LastPadding=aaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbcccccccccccccccccccdddddddddddeeeeeeee",
            "flowEndMicroseconds": "2016-11-11T12:09:19.000#{nanos}Z",
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
            "flowStartMicroseconds": "2016-11-11T12:09:19.000#{nanos}Z",
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

    if Gem::Requirement.create('>= 8.0').satisfied_by?(Gem::Version.create(LOGSTASH_CORE_VERSION))
      it "should decode raw data decoding flowEndMicroseconds with nano precision" do
        expect(decode[0].get("[netflow][flowEndMicroseconds]")).to eq('2016-11-11T12:09:19.000127768Z')
      end
    else
      it "should decode raw data decoding flowEndMicroseconds with millis precision" do
        expect(decode[0].get("[netflow][flowEndMicroseconds]")).to eq('2016-11-11T12:09:19.000Z')
      end
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
          "vmwareIngressInterfaceAttr": 1,
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
          "vmwareEgressInterfaceAttr": 2,
          "flowStartMilliseconds": "2016-12-22T12:17:37.000Z",
          "vmwareVxlanExportRole": 0
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
             "first_switched":"2016-12-23T01:34:52.569Z",
             "flowset_id":256,
             "l4_src_port":0,
             "src_mask":32,
             "version":9,
             "flow_seq_num":100728833,
             "ipv4_src_addr":"192.168.1.33",
             "in_bytes":0,
             "protocol":2,
             "input_snmp":2,
             "last_switched":"2016-12-23T01:34:52.569Z",
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
    end

    it "should decode raw data" do
      expect(decode.size).to eq(10)
      expect(decode[9].get("[netflow][ipv4_src_addr]")).to eq("192.168.1.33")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[9].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end

  context "Netflow 9 Cisco ASR 9000 series options template 256" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_cisco_asr9k_opttpl256.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_cisco_asr9k_data256.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "netflow": {
            "flow_seq_num": 24496783,
            "scope_system": 3250896451,
            "input_snmp": 104,
            "if_desc": "TenGigE0_6_0_2",
            "flowset_id": 256,
            "version": 9
          },
          "@timestamp": "2016-12-06T10:09:48.000Z",
          "@version": "1"
        }
        END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(19)
      expect(decode[18].get("[netflow][if_desc]")).to eq("TenGigE0_6_0_2")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[18].to_json)).to eq(JSON.parse(json_events[0]))
    end

  end


  context "Netflow 9 Huawei Netstream" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_huawei_netstream_tpl.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_huawei_netstream_data.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@version": "1",
          "netflow": {
            "dst_as": 0,
            "rev_flow_delta_bytes": 0,
            "forwarding_status": {
              "reason": 0,
              "status": 0
            },
            "in_pkts": 4,
            "first_switched": "2018-01-29T02:56:52.940Z",
            "flowset_id": 1315,
            "ipv4_next_hop": "10.108.252.41",
            "l4_src_port": 45587,
            "src_vlan": 0,
            "in_bytes": 200,
            "protocol": 6,
            "tcp_flags": 24,
            "dst_vlan": 0,
            "l4_dst_port": 2598,
            "src_as": 0,
            "direction": 1,
            "output_snmp": 31,
            "dst_mask": 25,
            "ipv4_dst_addr": "10.111.112.204",
            "src_tos": 0,
            "src_mask": 24,
            "version": 9,
            "flow_seq_num": 129954,
            "ipv4_src_addr": "10.108.219.53",
            "last_switched": "2018-01-29T03:02:20.000Z",
            "input_snmp": 8,
            "bgp_ipv4_next_hop": "0.0.0.0"
          },
          "@timestamp": "2018-01-29T03:02:20.000Z"
        }
        END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(1)
      expect(decode[0].get("[netflow][rev_flow_delta_bytes]")).to eq(0)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
    end
  end


  context "Netflow 9 field layer2segmentid" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_field_layer2segmentid_tpl.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_field_layer2segmentid_data.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@version": "1",
          "netflow": {
            "in_pkts": 1,
            "ipv4_dst_addr": "80.82.237.40",
            "src_tos": 0,
            "first_switched": "2018-01-16T09:44:48.000Z",
            "flowset_id": 266,
            "l4_src_port": 61926,
            "version": 9,
            "flow_seq_num": 4773,
            "ipv4_src_addr": "192.168.200.136",
            "src_vlan": 3174,
            "protocol": 6,
            "in_bytes": 52,
            "input_snmp": 7,
            "last_switched": "2018-01-16T09:44:48.000Z",
            "flow_sampler_id": 98,
            "layer2SegmentId": 0,
            "ingressVRFID": 0,
            "l4_dst_port": 445,
            "direction": 0
          },
          "@timestamp": "2018-01-16T09:45:02.000Z"
        }
        END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(1)
      expect(decode[0].get("[netflow][layer2SegmentId]")).to eq(0)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
    end
  end


  context "Netflow 9 Cisco ASR 9000 series template 260" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_cisco_asr9k_tpl260.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_cisco_asr9k_data260.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "netflow": {
            "dst_as": 64498,
            "forwarding_status": {
              "reason": 0,
              "status": 1
            },
            "in_pkts": 2,
            "first_switched": "2016-12-06T10:08:53.377Z",
            "flowset_id": 260,
            "l4_src_port": 443,
            "in_bytes": 112,
            "protocol": 6,
            "tcp_flags": 18,
            "ingressVRFID": 1610612736,
            "l4_dst_port": 52364,
            "src_as": 15169,
            "direction": 1,
            "output_snmp": 158,
            "dst_mask": 24,
            "ipv4_dst_addr": "10.0.15.38",
            "src_tos": 0,
            "src_mask": 24,
            "version": 9,
            "flow_seq_num": 24495777,
            "ipv4_src_addr": "10.0.29.46",
            "egressVRFID": 1610612736,
            "input_snmp": 75,
            "last_switched": "2016-12-06T10:08:54.964Z",
            "flow_sampler_id": 1,
            "bgp_ipv4_next_hop": "10.0.14.27"
          },
          "@timestamp": "2016-12-06T10:09:24.000Z",
          "@version": "1"
        }
        END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(21)
      expect(decode[20].get("[netflow][egressVRFID]")).to eq(1610612736)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[20].to_json)).to eq(JSON.parse(json_events[0]))
    end
  end

  context "Netflow 9 Cisco NBAR options template 260" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_cisco_nbar_opttpl260.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "netflow": {
            "flow_seq_num": 655860,
            "scope_system": 168755571,
            "application_name": "argus",
            "application_description": "ARGUS",
            "flowset_id": 260,
            "version": 9,
            "application_id": "1..13"
          },
          "@timestamp": "2017-02-14T11:09:59.000Z",
          "@version": "1"
        }
        END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(15)
      expect(decode[14].get("[netflow][application_id]")).to eq("1..13")
      expect(decode[14].get("[netflow][application_description]")).to eq("ARGUS")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[14].to_json)).to eq(JSON.parse(json_events[0]))
    end
  end

  context "Netflow 9 Cisco NBAR flowset 262" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_cisco_nbar_tpl262.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_cisco_nbar_data262.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "netflow": {
            "dst_as": 0,
            "in_pkts": 36,
            "ipv4_src_prefix": "0.0.0.0",
            "first_switched": "2017-02-14T11:10:20.936Z",
            "flowset_id": 262,
            "l4_src_port": 45269,
            "ipv4_next_hop": "0.0.0.0",
            "protocol": 17,
            "in_bytes": 2794,
            "tcp_src_port": 0,
            "l4_dst_port": 161,
            "direction": 0,
            "src_as": 0,
            "output_snmp": 0,
            "ip_dscp": 0,
            "ipv4_ident": 0,
            "ipv4_dst_addr": "10.30.19.180",
            "src_tos": 0,
            "in_dst_mac": "1c:df:0f:7e:c3:58",
            "udp_dst_port": 161,
            "src_mask": 0,
            "version": 9,
            "application_id": "5..38",
            "flow_seq_num": 1509134,
            "ipv4_src_addr": "10.10.172.60",
            "in_src_mac": "00:18:19:9e:6c:01",
            "input_snmp": 1,
            "last_switched": "2017-02-14T11:10:21.008Z",
            "flow_sampler_id": 0
          },
          "@timestamp": "2017-02-14T11:10:36.000Z",
          "@version": "1"
        }
        END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(5)
      expect(decode[4].get("[netflow][application_id]")).to eq("5..38")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[4].to_json)).to eq(JSON.parse(json_events[0]))
    end
  end

  context "Netflow 9 Cisco WLC" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_cisco_wlc_tpl.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_cisco_wlc_data261.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "netflow": {
            "ip_dscp": 0,
            "in_pkts": 53362,
            "wtpMacAddress": "00:f6:63:cc:80:60",
            "staMacAddress": "34:02:86:75:c0:51",
            "flowset_id": 261,
            "version": 9,
            "application_id": "13..431",
            "flow_seq_num": 78,
            "in_bytes": 80973880,
            "postIpDiffServCodePoint": 0,
            "wlanSSID": "Test-env",
            "staIPv4Address": "192.168.20.121",
            "direction": 1
          },
          "@timestamp": "2017-06-22T06:31:14.000Z",
          "@version": "1"
        }
        END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(19)
      expect(decode[18].get("[netflow][application_id]")).to eq("13..431")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[18].to_json)).to eq(JSON.parse(json_events[0]))
    end
  end

  context "Netflow 9 Cisco WLC 8500 release 8.2 " do
    let(:data) do
      data = []
      data << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_cisco_wlc_8510_tpl_262.dat"), :mode => "rb")
    end

    it "should not raise_error" do
      expect{decode.size}.not_to raise_error
    end
  end
  
  context "Netflow 9 Cisco 1941/K9 release 15.1 " do
    let(:data) do
      data = []
      data << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_cisco_1941K9.dat"), :mode => "rb")
    end

    it "should not raise_error" do
      expect{decode.size}.not_to raise_error
    end
  end

  context "Netflow 9 Cisco ASR1001-X " do
    let(:data) do
      data = []
      data << IO.read(File.join(File.dirname(__FILE__), "netflow9_cisco_asr1001x_tpl259.dat"), :mode => "rb")
    end

    it "should not raise_error" do
      expect{decode.size}.not_to raise_error
    end
  end

  context "Netflow 9 Palo Alto PAN-OS with app-id" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_paloalto_panos_tpl.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_paloalto_panos_data.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "netflow": {
            "output_snmp": 23,
            "icmp_type": 0,
            "in_pkts": 1,
            "src_tos": 0,
            "ipv4_dst_addr": "162.115.24.30",
            "first_switched": "2017-11-13T14:33:53.000Z",
            "flowset_id": 257,
            "l4_src_port": 39702,
            "fw_event": 5,
            "version": 9,
            "flow_seq_num": 207392627,
            "ipv4_src_addr": "10.32.105.103",
            "in_bytes": 111,
            "protocol": 6,
            "tcp_flags": 26,
            "input_snmp": 24,
            "last_switched": "2017-11-13T14:39:32.000Z",
            "user_id": "",
            "conn_id": 415347,
            "privateEnterpriseNumber": 25461,
            "l4_dst_port": 443,
            "app_id": "ssl",
            "direction": 0
          },
          "@version": "1",
          "@timestamp": "2017-11-13T14:39:31.000Z"
        }
        END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(8)
      expect(decode[7].get("[netflow][app_id]")).to eq("incomplete")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[1].to_json)).to eq(JSON.parse(json_events[0]))
    end
  end

  context "IPFIX vIPtela with VPN id" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_viptela_tpl257.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_viptela_data257.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@version": "1",
          "netflow": {
            "destinationTransportPort": 443,
            "icmpTypeCodeIPv4": 0,
            "sourceIPv4Address": "10.113.7.54",
            "ipClassOfService": 48,
            "ipPrecedence": 1,
            "maximumIpTotalLength": 277,
            "egressInterface": 3,
            "octetDeltaCount": 775,
            "ipNextHopIPv4Address": "10.0.0.1",
            "sourceTransportPort": 41717,
            "viptelaVPNId": 100,
            "destinationIPv4Address": "172.16.21.27",
            "octetTotalCount": 775,
            "minimumIpTotalLength": 70,
            "ipDiffServCodePoint": 12,
            "tcpControlBits": 16,
            "ingressInterface": 11,
            "version": 10,
            "packetDeltaCount": 8,
            "flowEndReason": 3,
            "protocolIdentifier": 6,
            "flowEndSeconds": "2017-11-21T14:32:15.000Z",
            "flowStartSeconds": "2017-11-21T14:32:15.000Z",
            "packetTotalCount": 8
          },
          "@timestamp": "2017-11-21T14:32:15.000Z"
        }
        END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(1)
      expect(decode[0].get("[netflow][viptelaVPNId]")).to eq(100)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
    end
  end



  context "IPFIX Barracuda firewall" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_barracuda_tpl.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_barracuda_data256.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "netflow": {
            "destinationIPv4Address": "10.99.168.140",
            "octetTotalCount": 113,
            "destinationTransportPort": 50294,
            "flowStartSysUpTime": 2395374954,
            "sourceIPv4Address": "10.98.243.20",
            "flowEndSysUpTime": 2395395322,
            "flowDurationMilliseconds": 20368,
            "ingressInterface": 41874,
            "version": 10,
            "packetDeltaCount": 1,
            "firewallEvent": 2,
            "protocolIdentifier": 17,
            "sourceMacAddress": "00:00:00:00:00:00",
            "egressInterface": 48660,
            "octetDeltaCount": 113,
            "sourceTransportPort": 53,
            "packetTotalCount": 1
          },
          "@timestamp": "2017-06-29T13:58:28.000Z",
          "@version": "1"
        }
        END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(8)
      expect(decode[7].get("[netflow][firewallEvent]")).to eq(2)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[7].to_json)).to eq(JSON.parse(json_events[0]))
    end
  end

  context "IPFIX YAF basic with applabel" do
    # These samples have been generated with:
    # /usr/local/bin/yaf --silk --ipfix=udp --live=pcap --out=host02 --ipfix-port=2055 --in=eth0 --applabel --verbose --mac --verbose --max-payload 384
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_yaf_tpls_option_tpl.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_yaf_tpl45841.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_yaf_data45841.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_yaf_data45873.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "ipfix_test_yaf_data53248.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
      {
        "netflow": {
          "destinationIPv4Address": "172.16.32.100",
          "octetTotalCount": 132,
          "destinationTransportPort": 53,
          "vlanId": 0,
          "reversePacketTotalCount": 2,
          "reverseFlowDeltaMilliseconds": 1,
          "sourceIPv4Address": "172.16.32.201",
          "reverseVlanId": 0,
          "reverseIpClassOfService": 0,
          "reverseOctetTotalCount": 200,
          "reverseFlowAttributes": 0,
          "ipClassOfService": 0,
          "version": 10,
          "flowEndReason": 1,
          "protocolIdentifier": 17,
          "silkAppLabel": 53,
          "sourceTransportPort": 46086,
          "packetTotalCount": 2,
          "flowEndMilliseconds": "2016-12-25T12:58:35.819Z",
          "flowStartMilliseconds": "2016-12-25T12:58:35.818Z",
          "flowAttributes": 1
        },
        "@timestamp": "2016-12-25T13:03:38.000Z",
        "@version": "1"
      }
      END

      events << <<-END
      {
        "netflow": {
          "destinationTransportPort": 9997,
          "reversePacketTotalCount": 2,
          "reverseFlowDeltaMilliseconds": 0,
          "sourceIPv4Address": "172.16.32.100",
          "reverseTcpSequenceNumber": 3788795034,
          "reverseVlanId": 0,
          "reverseOctetTotalCount": 92,
          "ipClassOfService": 2,
          "reverseInitialTCPFlags": 18,
          "tcpSequenceNumber": 340533701,
          "silkAppLabel": 0,
          "sourceTransportPort": 63499,
          "flowEndMilliseconds": "2016-12-25T12:58:34.347Z",
          "flowAttributes": 0,
          "destinationIPv4Address": "172.16.32.215",
          "octetTotalCount": 172,
          "vlanId": 0,
          "reverseIpClassOfService": 0,
          "reverseFlowAttributes": 0,
          "unionTCPFlags": 17,
          "version": 10,
          "flowEndReason": 3,
          "protocolIdentifier": 6,
          "initialTCPFlags": 194,
          "reverseUnionTCPFlags": 17,
          "packetTotalCount": 4,
          "flowStartMilliseconds": "2016-12-25T12:58:33.345Z"
        },
        "@timestamp": "2016-12-25T12:58:38.000Z",
        "@version": "1"
      }
      END

      events << <<-END
      {
        "netflow": {
          "droppedPacketTotalCount": 0,
          "exporterIPv4Address": "172.16.32.201",
          "ignoredPacketTotalCount": 58,
          "meanPacketRate": 6,
          "flowTableFlushEventCount": 39,
          "flowTablePeakCount": 58,
          "version": 10,
          "exportedFlowRecordTotalCount": 31,
          "systemInitTimeMilliseconds": 1482670712000,
          "notSentPacketTotalCount": 0,
          "exportingProcessId": 0,
          "meanFlowRate": 0,
          "expiredFragmentCount": 0,
          "assembledFragmentCount": 0,
          "packetTotalCount": 1960
        },
        "@timestamp": "2016-12-25T13:03:33.000Z",
        "@version": "1"
      }
      END
    end

    it "should decode raw data" do
      expect(decode.size).to eq(3)
      expect(decode[0].get("[netflow][silkAppLabel]")).to eq(53)
      expect(decode[1].get("[netflow][initialTCPFlags]")).to eq(194)
      expect(decode[2].get("[netflow][flowTablePeakCount]")).to eq(58)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
      expect(JSON.parse(decode[1].to_json)).to eq(JSON.parse(json_events[1]))
      expect(JSON.parse(decode[2].to_json)).to eq(JSON.parse(json_events[2]))
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
    end

    it "should report missing templates" do
      expect(logger).to receive(:warn).with(/Can't \(yet\) decode flowset id/)
      decode[0]
    end
  end
end

# New subject with config, ordered testing since we need caching before data processing
describe LogStash::Codecs::Netflow, 'configured with template caching', :order => :defined do
  let(:is_LS_8) do
    logstash_version = Gem::Version.create(LOGSTASH_CORE_VERSION)
    Gem::Requirement.create('>= 8.0').satisfied_by?(logstash_version)
  end

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

    # in LS 8 the precision is up to nanos in LS 7 is up to millis
    let(:nanos) { is_LS_8 ? "127768" : "" }

    it "should decode raw data based on cached templates" do
      expect(decode.size).to eq(3)
      expect(decode[0].get("[netflow][version]")).to eq(10)
      expect(decode[0].get("[netflow][flowEndMicroseconds]")).to eq("2016-11-11T12:09:19.000#{nanos}Z")
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
    expect(decode[0].get("[netflow][netscalerConnectionId]")).to eq(14460661)
    expect(decode[1].get("[netflow][version]")).to eq(10)
    expect(decode[1].get("[netflow][observationPointId]")).to eq(167954698)
    expect(decode[1].get("[netflow][netscalerFlowFlags]")).to eq(1157636096)
    expect(decode[2].get("[netflow][version]")).to eq(10)
    expect(decode[2].get("[netflow][netscalerAppUnitNameAppId]")).to eq(239927296)
  end

  if Gem::Requirement.create('>= 8.0').satisfied_by?(Gem::Version.create(LOGSTASH_CORE_VERSION))
    it "should decode raw data decoding flowEndMicroseconds with nano precision" do
      expect(decode[0].get("[netflow][flowEndMicroseconds]")).to eq('2016-11-11T12:09:19.000127768Z')
    end
  else
    it "should decode raw data decoding flowEndMicroseconds with millis precision" do
      expect(decode[0].get("[netflow][flowEndMicroseconds]")).to eq('2016-11-11T12:09:19.000Z')
    end
  end

  it "should include flowset_id" do
    expect(decode[0].get("[netflow][flowset_id]")).to eq(258)
    expect(decode[1].get("[netflow][flowset_id]")).to eq(257)
    expect(decode[2].get("[netflow][flowset_id]")).to eq(258)
  end


end
