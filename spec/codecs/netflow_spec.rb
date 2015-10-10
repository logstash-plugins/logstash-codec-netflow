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

  context "Netflow 5" do
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
      data = []
      data << IO.read(File.join(File.dirname(__FILE__), "netflow9.dat"), :mode => "rb")
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
      expect(decode[0]["[netflow][in_src_mac]"]).to eq("00:50:56:c0:00:01")
      expect(decode[0]["[netflow][in_dst_mac]"]).to eq("00:0c:29:70:86:09")
    end

    it "should serialize to json" do
      expect(JSON.parse(decode[0].to_json)).to eq(JSON.parse(json_events[0]))
    end
  end
end
