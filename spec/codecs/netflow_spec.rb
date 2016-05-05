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
      expect(decode[0].get("[netflow][in_src_mac]")).to eq("00:50:56:c0:00:01")
      expect(decode[0].get("[netflow][in_dst_mac]")).to eq("00:0c:29:70:86:09")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
    end
  end

  context "Netflow 9 Cisco ASA" do
    let(:data) do
      packets = []
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_valid_cisco_asa_tpl.dat"), :mode => "rb")
      packets << IO.read(File.join(File.dirname(__FILE__), "netflow9_test_valid_cisco_asa_data.dat"), :mode => "rb")
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
      expect(decode.size).to eq(8)
      expect(decode[0].get("[netflow][l4_src_port]")).to eq(123)
      expect(decode[7].get("[netflow][l4_src_port]")).to eq(22)
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
      expect(JSON.parse(decode[7].to_json)).to eq(JSON.parse(json_events[1]))
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
end
