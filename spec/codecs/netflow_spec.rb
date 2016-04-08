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
      subject.decode(data){|event| events << event}
    end
  end

  context "Netflow 5" do
    let(:data) do
      # this netflow raw data was produced with softflowd and captured with netcat
      # softflowd -D -i eth0 -v 5 -t maxlife=1 -n 127.0.01:8765
      # nc -k -4 -u -l 127.0.0.1 8765 > netflow5.dat
      IO.read(File.join(File.dirname(__FILE__), "netflow5.dat"), :mode => "rb")
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

      expect(decode[0]["[netflow][version]"]).to eq(5)
      expect(decode[0]["[netflow][ipv4_src_addr]"]).to eq("10.0.2.2")
      expect(decode[0]["[netflow][ipv4_dst_addr]"]).to eq("10.0.2.15")
      expect(decode[0]["[netflow][l4_src_port]"]).to eq(54435)
      expect(decode[0]["[netflow][l4_dst_port]"]).to eq(22)
      expect(decode[0]["[netflow][tcp_flags]"]).to eq(16)

      expect(decode[1]["[netflow][version]"]).to eq(5)
      expect(decode[1]["[netflow][ipv4_src_addr]"]).to eq("10.0.2.15")
      expect(decode[1]["[netflow][ipv4_dst_addr]"]).to eq("10.0.2.2")
      expect(decode[1]["[netflow][l4_src_port]"]).to eq(22)
      expect(decode[1]["[netflow][l4_dst_port]"]).to eq(54435)
      expect(decode[1]["[netflow][tcp_flags]"]).to eq(24)
    end

    it "should serialize to json" do
      # generated json order can change with different implementation, convert back to hash to compare.
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
      expect(JSON.parse(decode[1].to_json)).to eq(JSON.parse(json_events[1]))
    end
  end

  context "Netflow 9" do
    let(:data) do
      # this netflow raw data was produced with softflowd and captured with netcat
      # softflowd -D -i eth0 -v 9 -t maxlife=1 -n 127.0.01:8765
      # nc -k -4 -u -l 127.0.0.1 8765 > netflow9.dat
      IO.read(File.join(File.dirname(__FILE__), "netflow9.dat"), :mode => "rb")
    end

    let(:json_events) do
      events = []
      events << <<-END
        {
          "@timestamp": "2015-05-02T22:10:07.000Z",
          "netflow": {
            "version": 9,
            "flow_seq_num": 0,
            "flowset_id": 1024,
            "ipv4_src_addr": "10.0.2.2",
            "ipv4_dst_addr": "10.0.2.15",
            "last_switched": "2015-05-02T22:10:07.999Z",
            "first_switched": "2015-06-21T15:12:49.999Z",
            "in_bytes": 230,
            "in_pkts": 5,
            "input_snmp": 0,
            "output_snmp": 0,
            "l4_src_port": 57369,
            "l4_dst_port": 22,
            "protocol": 6,
            "tcp_flags": 16,
            "ip_protocol_version": 4
          },
          "@version": "1"
        }
      END

      events << <<-END
        {
          "@timestamp": "2015-05-02T22:10:07.000Z",
          "netflow": {
            "version": 9,
            "flow_seq_num": 0,
            "flowset_id": 1024,
            "ipv4_src_addr": "10.0.2.15",
            "ipv4_dst_addr": "10.0.2.2",
            "last_switched": "2015-05-02T22:10:07.999Z",
            "first_switched": "2015-06-21T15:12:49.999Z",
            "in_bytes": 352,
            "in_pkts": 4,
            "input_snmp": 0,
            "output_snmp": 0,
            "l4_src_port": 22,
            "l4_dst_port": 57369,
            "protocol": 6,
            "tcp_flags": 24,
            "ip_protocol_version": 4
          },
          "@version": "1"
        }
      END

      events.map{|event| event.gsub(/\s+/, "")}
    end

    it "should decode raw data" do
      expect(decode.size).to eq(2)

      expect(decode[0]["[netflow][version]"]).to eq(9)
      expect(decode[0]["[netflow][ipv4_src_addr]"]).to eq("10.0.2.2")
      expect(decode[0]["[netflow][ipv4_dst_addr]"]).to eq("10.0.2.15")
      expect(decode[0]["[netflow][l4_src_port]"]).to eq(57369)
      expect(decode[0]["[netflow][l4_dst_port]"]).to eq(22)
      expect(decode[0]["[netflow][tcp_flags]"]).to eq(16)

      expect(decode[1]["[netflow][version]"]).to eq(9)
      expect(decode[1]["[netflow][ipv4_src_addr]"]).to eq("10.0.2.15")
      expect(decode[1]["[netflow][ipv4_dst_addr]"]).to eq("10.0.2.2")
      expect(decode[1]["[netflow][l4_src_port]"]).to eq(22)
      expect(decode[1]["[netflow][l4_dst_port]"]).to eq(57369)
      expect(decode[1]["[netflow][tcp_flags]"]).to eq(24)
    end

    it "should serialize to json" do
      # generated json order can change with different implementation, convert back to hash to compare.
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
      expect(JSON.parse(decode[1].to_json)).to eq(JSON.parse(json_events[1]))
    end
  end

  context "IPFIX" do
    let(:data) do
      # this netflow raw data was produced with softflowd and captured with netcat
      # softflowd -D -i eth0 -v 10 -t maxlife=1 -n 127.0.01:8765
      # nc -k -4 -u -l 127.0.0.1 8765 > ipfix.dat
      IO.read(File.join(File.dirname(__FILE__), "ipfix.dat"), :mode => "rb")
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

      expect(decode[0]["[netflow][version]"]).to eq(10)
      expect(decode[0]["[netflow][systemInitTimeMilliseconds]"]).to eq(1431516013506)

      expect(decode[1]["[netflow][version]"]).to eq(10)
      expect(decode[1]["[netflow][sourceIPv4Address]"]).to eq("192.168.253.1")
      expect(decode[1]["[netflow][destinationIPv4Address]"]).to eq("192.168.253.128")
      expect(decode[1]["[netflow][sourceTransportPort]"]).to eq(60560)
      expect(decode[1]["[netflow][destinationTransportPort]"]).to eq(22)
      expect(decode[1]["[netflow][protocolIdentifier]"]).to eq(6)
      expect(decode[1]["[netflow][tcpControlBits]"]).to eq(16)

      expect(decode[2]["[netflow][version]"]).to eq(10)
      expect(decode[2]["[netflow][sourceIPv4Address]"]).to eq("192.168.253.128")
      expect(decode[2]["[netflow][destinationIPv4Address]"]).to eq("192.168.253.1")
      expect(decode[2]["[netflow][sourceTransportPort]"]).to eq(22)
      expect(decode[2]["[netflow][destinationTransportPort]"]).to eq(60560)
      expect(decode[2]["[netflow][protocolIdentifier]"]).to eq(6)
      expect(decode[2]["[netflow][tcpControlBits]"]).to eq(24)

      expect(decode[3]["[netflow][sourceIPv4Address]"]).to eq("192.168.253.2")
      expect(decode[3]["[netflow][destinationIPv4Address]"]).to eq("192.168.253.132")
      expect(decode[3]["[netflow][sourceTransportPort]"]).to eq(53)
      expect(decode[3]["[netflow][destinationTransportPort]"]).to eq(35262)
      expect(decode[3]["[netflow][protocolIdentifier]"]).to eq(17)

      expect(decode[4]["[netflow][sourceIPv4Address]"]).to eq("192.168.253.132")
      expect(decode[4]["[netflow][destinationIPv4Address]"]).to eq("192.168.253.2")
      expect(decode[4]["[netflow][sourceTransportPort]"]).to eq(35262)
      expect(decode[4]["[netflow][destinationTransportPort]"]).to eq(53)
      expect(decode[4]["[netflow][protocolIdentifier]"]).to eq(17)

      expect(decode[5]["[netflow][sourceIPv4Address]"]).to eq("54.214.9.161")
      expect(decode[5]["[netflow][destinationIPv4Address]"]).to eq("192.168.253.132")
      expect(decode[5]["[netflow][sourceTransportPort]"]).to eq(443)
      expect(decode[5]["[netflow][destinationTransportPort]"]).to eq(49935)
      expect(decode[5]["[netflow][protocolIdentifier]"]).to eq(6)
      expect(decode[5]["[netflow][tcpControlBits]"]).to eq(26)

      expect(decode[6]["[netflow][sourceIPv4Address]"]).to eq("192.168.253.132")
      expect(decode[6]["[netflow][destinationIPv4Address]"]).to eq("54.214.9.161")
      expect(decode[6]["[netflow][sourceTransportPort]"]).to eq(49935)
      expect(decode[6]["[netflow][destinationTransportPort]"]).to eq(443)
      expect(decode[6]["[netflow][protocolIdentifier]"]).to eq(6)
      expect(decode[6]["[netflow][tcpControlBits]"]).to eq(26)
    end

    it "should serialize to json" do
      expect(decode[0].to_json).to eq(json_events[0])
      expect(decode[1].to_json).to eq(json_events[1])
      expect(decode[2].to_json).to eq(json_events[2])
      expect(decode[3].to_json).to eq(json_events[3])
      expect(decode[4].to_json).to eq(json_events[4])
      expect(decode[5].to_json).to eq(json_events[5])
      expect(decode[6].to_json).to eq(json_events[6])
    end
  end
end
