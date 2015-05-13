# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "logstash/timestamp"

# The "netflow" codec is for decoding Netflow v5/v9/v10 (IPFIX) flows.

# Example:
#
#     input {
#       udp {
#         host => localhost
#         port => 2055
#         codec => netflow {
#           versions => [5, 9]
#         }
#         type => netflow
#       }
#       udp {
#         host => localhost
#         port => 4739
#         codec => netflow {
#           versions => [10]
#           target => ipfix
#         }
#         type => ipfix
#       }
#       tcp {
#         host => localhost
#         port => 4739
#         codec => netflow {
#           versions => [10]
#           target => ipfix
#         }
#         type => ipfix
#       }
#     }
class LogStash::Codecs::Netflow < LogStash::Codecs::Base
  config_name "netflow"

  # Netflow v9 template cache TTL (minutes)
  config :cache_ttl, :validate => :number, :default => 4000

  # Specify into what field you want the Netflow data.
  config :target, :validate => :string, :default => "netflow"

  # Specify which Netflow versions you will accept.
  config :versions, :validate => :array, :default => [5, 9, 10]

  # Override YAML file containing Netflow field definitions
  #
  # Each Netflow field is defined like so:
  #
  #    ---
  #    id:
  #    - default length in bytes
  #    - :name
  #    id:
  #    - :uintN or :ip4_addr or :ip6_addr or :mac_addr or :string
  #    - :name
  #    id:
  #    - :skip
  #
  # See <https://github.com/logstash-plugins/logstash-codec-netflow/blob/master/lib/logstash/codecs/netflow/netflow.yaml> for the base set.
  config :netflow_definitions, :validate => :path

  # Override YAML file containing IPFIX field definitions
  #
  # Very similar to the Netflow version except there is a top level Private
  # Enterprise Number (PEN) key added:
  #
  #    ---
  #    pen:
  #      id:
  #      - :uintN or :ip4_addr or :ip6_addr or :mac_addr or :string
  #      - :name
  #      id:
  #      - :skip
  #
  # There is an implicit PEN 0 for the standard fields.
  #
  # See <https://github.com/logstash-plugins/logstash-codec-netflow/blob/master/lib/logstash/codecs/netflow/ipfix.yaml> for the base set.
  config :ipfix_definitions, :validate => :path

  NETFLOW5_FIELDS = ['version', 'flow_seq_num', 'engine_type', 'engine_id', 'sampling_algorithm', 'sampling_interval', 'flow_records']
  NETFLOW9_FIELDS = ['version', 'flow_seq_num']
  IPFIX_FIELDS = ['version']
  SWITCHED = /_switched$/
  FLOWSET_ID = "flowset_id"

  def initialize(params = {})
    super(params)
    @threadsafe = false
  end

  def register
    require "logstash/codecs/netflow/util"
    @netflow_templates = Vash.new()
    @ipfix_templates = Vash.new()

    # Path to default Netflow v9 field definitions
    filename = ::File.expand_path('netflow/netflow.yaml', ::File.dirname(__FILE__))
    @netflow_fields = load_definitions(filename, @netflow_definitions)

    # Path to default IPFIX field definitions
    filename = ::File.expand_path('netflow/ipfix.yaml', ::File.dirname(__FILE__))
    @ipfix_fields = load_definitions(filename, @ipfix_definitions)
  end # def register

  def decode(payload, &block)
    header = Header.read(payload)

    unless @versions.include?(header.version)
      @logger.warn("Ignoring Netflow version v#{header.version}")
      return
    end

    if header.version == 5
      flowset = Netflow5PDU.read(payload)
      flowset.records.each do |record|
        yield(decode_netflow5(flowset, record))
      end
    elsif header.version == 9
      flowset = Netflow9PDU.read(payload)
      flowset.records.each do |record|
        decode_netflow9(flowset, record).each{|event| yield(event)}
      end
    elsif header.version == 10
      BinData::trace_reading do
        flowset = IpfixPDU.read(payload)
        flowset.records.each do |record|
          decode_ipfix(flowset, record).each { |event| yield(event) }
        end
      end
    else
      @logger.warn("Unsupported Netflow version v#{header.version}")
    end
  end

  private

  def decode_netflow5(flowset, record)
    event = {
      LogStash::Event::TIMESTAMP => LogStash::Timestamp.at(flowset.unix_sec.snapshot, flowset.unix_nsec.snapshot / 1000),
      @target => {}
    }

    # Copy some of the pertinent fields in the header to the event
    NETFLOW5_FIELDS.each do |f|
      event[@target][f] = flowset[f].snapshot
    end

    # Create fields in the event from each field in the flow record
    record.each_pair do |k, v|
      case k.to_s
      when SWITCHED
        # The flow record sets the first and last times to the device
        # uptime in milliseconds. Given the actual uptime is provided
        # in the flowset header along with the epoch seconds we can
        # convert these into absolute times
        millis = flowset.uptime - v
        seconds = flowset.unix_sec - (millis / 1000)
        micros = (flowset.unix_nsec / 1000) - (millis % 1000)
        if micros < 0
          seconds--
          micros += 1000000
        end
        event[@target][k.to_s] = LogStash::Timestamp.at(seconds, micros).to_iso8601
      else
        event[@target][k.to_s] = v.snapshot
      end
    end

    LogStash::Event.new(event)
  end

  def decode_netflow9(flowset, record)
    events = []

    case record.flowset_id
    when 0
      # Template flowset
      record.flowset_data.templates.each do |template|
        catch (:field) do
          fields = []
          template.fields.each do |field|
            entry = netflow_field_for(field.field_type, field.field_length)
            throw :field unless entry
            fields += entry
          end
          # We get this far, we have a list of fields
          #key = "#{flowset.source_id}|#{event["source"]}|#{template.template_id}"
          key = "#{flowset.source_id}|#{template.template_id}"
          @netflow_templates[key, @cache_ttl] = BinData::Struct.new(:endian => :big, :fields => fields)
          # Purge any expired templates
          @netflow_templates.cleanup!
        end
      end
    when 1
      # Options template flowset
      record.flowset_data.templates.each do |template|
        catch (:field) do
          fields = []
          template.option_fields.each do |field|
            entry = netflow_field_for(field.field_type, field.field_length)
            throw :field unless entry
            fields += entry
          end
          # We get this far, we have a list of fields
          #key = "#{flowset.source_id}|#{event["source"]}|#{template.template_id}"
          key = "#{flowset.source_id}|#{template.template_id}"
          @netflow_templates[key, @cache_ttl] = BinData::Struct.new(:endian => :big, :fields => fields)
          # Purge any expired templates
          @netflow_templates.cleanup!
        end
      end
    when 256..65535
      # Data flowset
      #key = "#{flowset.source_id}|#{event["source"]}|#{record.flowset_id}"
      key = "#{flowset.source_id}|#{record.flowset_id}"
      template = @netflow_templates[key]

      unless template
        #@logger.warn("No matching template for flow id #{record.flowset_id} from #{event["source"]}")
        @logger.warn("No matching template for flow id #{record.flowset_id}")
        next
      end

      length = record.flowset_length - 4

      # Template shouldn't be longer than the record and there should
      # be at most 3 padding bytes
      if template.num_bytes > length or ! (length % template.num_bytes).between?(0, 3)
        @logger.warn("Template length doesn't fit cleanly into flowset", :template_id => record.flowset_id, :template_length => template.num_bytes, :record_length => length)
        next
      end

      array = BinData::Array.new(:type => template, :initial_length => length / template.num_bytes)
      records = array.read(record.flowset_data)

      records.each do |r|
        event = {
          LogStash::Event::TIMESTAMP => LogStash::Timestamp.at(flowset.unix_sec),
          @target => {}
        }

        # Fewer fields in the v9 header
        NETFLOW9_FIELDS.each do |f|
          event[@target][f] = flowset[f].snapshot
        end

        event[@target][FLOWSET_ID] = record.flowset_id.snapshot

        r.each_pair do |k, v|
          case k.to_s
          when SWITCHED
            millis = flowset.uptime - v
            seconds = flowset.unix_sec - (millis / 1000)
            # v9 did away with the nanosecs field
            micros = 1000000 - (millis % 1000)
            event[@target][k.to_s] = LogStash::Timestamp.at(seconds, micros).to_iso8601
          else
            event[@target][k.to_s] = v.snapshot
          end
        end

        events << LogStash::Event.new(event)
      end
    else
      @logger.warn("Unsupported flowset id #{record.flowset_id}")
    end

    events
  end

  def decode_ipfix(flowset, record)
    events = []

    case record.flowset_id
    when 2
      # Template flowset
      record.flowset_data.templates.each do |template|
        catch (:field) do
          fields = []
          template.fields.each do |field|
            field_type = field.field_type
            field_length = field.field_length
            enterprise_id = field.enterprise ? field.enterprise_id : 0

            if field.field_length == 0xffff
              # FIXME
              @logger.warn("Cowardly refusing to deal with variable length encoded field", :type => field_type, :enterprise => enterprise_id)
              throw :field
            end

            if enterprise_id == 0
              case field_type
              when 291, 292, 293
                # FIXME
                @logger.warn("Cowardly refusing to deal with complex data types", :type => field_type, :enterprise => enterprise_id)
                throw :field
              end
            end

            entry = ipfix_field_for(field_type, enterprise_id, field.field_length)
            throw :field unless entry
            fields += entry
          end
          # FIXME Source IP address required in key
          key = "#{flowset.observation_domain_id}|#{template.template_id}"
          @ipfix_templates[key, @cache_ttl] = BinData::Struct.new(:endian => :big, :fields => fields)
          # Purge any expired templates
          @ipfix_templates.cleanup!
        end
      end
    when 3
      # Options template flowset
      record.flowset_data.templates.each do |template|
        catch (:field) do
          fields = []
          (template.scope_fields.to_ary + template.option_fields.to_ary).each do |field|
            field_type = field.field_type
            field_length = field.field_length
            enterprise_id = field.enterprise ? field.enterprise_id : 0

            if field.field_length == 0xffff
              # FIXME
              @logger.warn("Cowardly refusing to deal with variable length encoded field", :type => field_type, :enterprise => enterprise_id)
              throw :field
            end

            if enterprise_id == 0
              case field_type
              when 291, 292, 293
                # FIXME
                @logger.warn("Cowardly refusing to deal with complex data types", :type => field_type, :enterprise => enterprise_id)
                throw :field
              end
            end

            entry = ipfix_field_for(field_type, enterprise_id, field.field_length)
            throw :field unless entry
            fields += entry
          end
          # FIXME Source IP address required in key
          key = "#{flowset.observation_domain_id}|#{template.template_id}"
          @ipfix_templates[key, @cache_ttl] = BinData::Struct.new(:endian => :big, :fields => fields)
          # Purge any expired templates
          @ipfix_templates.cleanup!
        end
      end
    when 256..65535
      # Data flowset
      key = "#{flowset.observation_domain_id}|#{record.flowset_id}"
      template = @ipfix_templates[key]

      unless template
        @logger.warn("No matching template for flow id #{record.flowset_id}")
        next
      end

      array = BinData::Array.new(:type => template, :read_until => :eof)
      records = array.read(record.flowset_data)

      records.each do |r|
        event = {
          LogStash::Event::TIMESTAMP => LogStash::Timestamp.at(flowset.unix_sec),
          @target => {}
        }

        IPFIX_FIELDS.each do |f|
          event[@target][f] = flowset[f].snapshot
        end

        r.each_pair do |k, v|
          case k.to_s
          when /^flow(?:Start|End)Seconds$/
            event[@target][k.to_s] = LogStash::Timestamp.at(v.snapshot).to_iso8601
          when /^flow(?:Start|End)(Milli|Micro|Nano)seconds$/
            divisor =
              case $1
              when 'Milli'
                1_000
              when 'Micro'
                1_000_000
              when 'Nano'
                1_000_000_000
              end
            event[@target][k.to_s] = LogStash::Timestamp.at(v.snapshot.to_f / divisor).to_iso8601
          else
            event[@target][k.to_s] = v.snapshot
          end
        end

        events << LogStash::Event.new(event)
      end
    else
      @logger.warn("Unsupported flowset id #{record.flowset_id}")
    end

    events
  end

  def load_definitions(defaults, extra)
    begin
      fields = YAML.load_file(defaults)
    rescue Exception => e
      raise "#{self.class.name}: Bad syntax in definitions file #{defaults}"
    end

    # Allow the user to augment/override/rename the default fields
    if extra
      raise "#{self.class.name}: definitions file #{extra} does not exist" unless File.exists?(extra)
      begin
        fields.merge!(YAML.load_file(extra))
      rescue Exception => e
        raise "#{self.class.name}: Bad syntax in definitions file #{extra}"
      end
    end

    fields
  end

  def uint_field(length, default)
    # If length is 4, return :uint32, etc. and use default if length is 0
    ("uint" + (((length > 0) ? length : default) * 8).to_s).to_sym
  end # def uint_field

  def netflow_field_for(type, length)
    if @netflow_fields.include?(type)
      field = @netflow_fields[type]
      if field.is_a?(Array)

        field[0] = uint_field(length, field[0]) if field[0].is_a?(Integer)

        # Small bit of fixup for skip or string field types where the length
        # is dynamic
        case field[0]
        when :skip
          field += [nil, {:length => length}]
        when :string
          field += [{:length => length, :trim_padding => true}]
        end

        @logger.debug? and @logger.debug("Definition complete", :field => field)

        [field]
      else
        @logger.warn("Definition should be an array", :field => field)
        nil
      end
    else
      @logger.warn("Unsupported field", :type => type, :length => length)
      nil
    end
  end # def netflow_field_for

  def ipfix_field_for(type, enterprise, length)
    if @ipfix_fields.include?(enterprise)
      if @ipfix_fields[enterprise].include?(type)
        field = @ipfix_fields[enterprise][type].clone
      else
        @logger.warn("Unsupported enterprise field", :type => type, :enterprise => enterprise, :length => length)
      end
    else
      @logger.warn("Unsupported enterprise", :enterprise => enterprise)
    end

    return nil unless field

    if field.is_a?(Array)
      case field[0]
      when :skip
        field += [nil, {:length => length}]
      when :string
        field += [{:length => length, :trim_padding => true}]
      when :uint64
        field[0] = uint_field(length, 8)
      when :uint32
        field[0] = uint_field(length, 4)
      when :uint16
        field[0] = uint_field(length, 2)
      end

      @logger.debug("Definition complete", :field => field)
      [field]
    else
      @logger.warn("Definition should be an array", :field => field)
    end
  end
end # class LogStash::Filters::Netflow
