# encoding: utf-8
require "logstash/codecs/base"
require "logstash/namespace"
require "logstash/timestamp"
#require "logstash/json"
require "json"

# Documentation moved to docs/

class LogStash::Codecs::Netflow < LogStash::Codecs::Base
  config_name "netflow"

  # Netflow v9/v10 template cache TTL (minutes)
  config :cache_ttl, :validate => :number, :default => 4000

  # Where to save the template cache
  # This helps speed up processing when restarting logstash
  # (So you don't have to await the arrival of templates)
  # cache will save as path/netflow_templates.cache and/or path/ipfix_templates.cache
  config :cache_save_path, :validate => :path

  # Specify into what field you want the Netflow data.
  config :target, :validate => :string, :default => "netflow"

  # Only makes sense for ipfix, v9 already includes this
  # Setting to true will include the flowset_id in events
  # Allows you to work with sequences, for instance with the aggregate filter
  config :include_flowset_id, :validate => :boolean, :default => false

  # Specify which Netflow versions you will accept.
  config :versions, :validate => :array, :default => [5, 9, 10]

  # Override YAML file containing Netflow field definitions
  config :netflow_definitions, :validate => :path

  # Override YAML file containing IPFIX field definitions
  config :ipfix_definitions, :validate => :path

  NETFLOW5_FIELDS = ['version', 'flow_seq_num', 'engine_type', 'engine_id', 'sampling_algorithm', 'sampling_interval', 'flow_records']
  NETFLOW9_FIELDS = ['version', 'flow_seq_num']
  NETFLOW9_SCOPES = {
    1 => :scope_system,
    2 => :scope_interface,
    3 => :scope_line_card,
    4 => :scope_netflow_cache,
    5 => :scope_template,
  }
  IPFIX_FIELDS = ['version']
  SWITCHED = /_switched$/
  FLOWSET_ID = "flowset_id"

  def initialize(params = {})
    @file_cache_mutex = Mutex.new
    super(params)
    @threadsafe = true
    @decode_mutex_netflow = Mutex.new
    @decode_mutex_ipfix = Mutex.new
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

    if @cache_save_path
      if @versions.include?(9)
        cache_save_file_netflow = "#{@cache_save_path}/netflow_templates.cache"
        if File.exists?(cache_save_file_netflow)
          raise "#{self.class.name}: Template cache file #{cache_save_file_netflow} not writable" unless File.writable?(cache_save_file_netflow)
          @netflow_templates_cache = load_templates_cache("#{@cache_save_path}/netflow_templates.cache")
          @netflow_templates_cache.each{ |key, fields| @netflow_templates[key, @cache_ttl] = BinData::Struct.new(:endian => :big, :fields => fields) }
        else
          raise "#{self.class.name}: Template cache directory #{cache_save_path} not writable" unless File.writable?(cache_save_path)
          @netflow_templates_cache = {}
        end
      end

      if @versions.include?(10)
        cache_save_file_ipfix = "#{@cache_save_path}/ipfix_templates.cache"
        if File.exists?(cache_save_file_ipfix)
          raise "#{self.class.name}: Template cache file #{cache_save_file_ipfix} not writable" unless File.writable?(cache_save_file_ipfix)
          @ipfix_templates_cache = load_templates_cache("#{@cache_save_path}/ipfix_templates.cache")
          @ipfix_templates_cache.each{ |key, fields| @ipfix_templates[key, @cache_ttl] = BinData::Struct.new(:endian => :big, :fields => fields) }
        else
          raise "#{self.class.name}: Template cache directory #{cache_save_path} not writable" unless File.writable?(cache_save_path)
          @ipfix_templates_cache = {}
        end
      end
    end
  end # def register

  def decode(payload, metadata = nil, &block)
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
#     BinData::trace_reading do
      flowset = Netflow9PDU.read(payload)
      flowset.records.each do |record|
        if metadata != nil
          decode_netflow9(flowset, record, metadata).each{|event| yield(event)}
        else
          decode_netflow9(flowset, record).each{|event| yield(event)}
        end
#      end
     end
    elsif header.version == 10
      flowset = IpfixPDU.read(payload)
      flowset.records.each do |record|
        decode_ipfix(flowset, record).each { |event| yield(event) }
      end
    else
      @logger.warn("Unsupported Netflow version v#{header.version}")
    end
  rescue BinData::ValidityError, IOError => e
    @logger.warn("Invalid netflow packet received (#{e})")
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
  rescue BinData::ValidityError, IOError => e
    @logger.warn("Invalid netflow packet received (#{e})")
  end

  def decode_netflow9(flowset, record, metadata = nil)
    events = []

    case record.flowset_id
    when 0..1
      # Template flowset
      record.flowset_data.templates.each do |template|
        catch (:field) do
          fields = []
          template_length = 0
          # Template flowset (0) or Options template flowset (1) ?
          if record.flowset_id == 0
            @logger.debug? and @logger.debug("Start processing template")
            template.record_fields.each do |field|
              if field.field_length > 0
                entry = netflow_field_for(field.field_type, field.field_length, template.template_id)
                throw :field unless entry
                fields += entry
                template_length += field.field_length
              end
            end
          else
            @logger.debug? and @logger.debug("Start processing options template")
            template.scope_fields.each do |field|
              if field.field_length > 0
                fields << [uint_field(0, field.field_length), NETFLOW9_SCOPES[field.field_type]]
              end
              template_length += field.field_length
            end
            template.option_fields.each do |field|
              entry = netflow_field_for(field.field_type, field.field_length, template.template_id)
              throw :field unless entry
              fields += entry
              template_length += field.field_length
            end
          end
          # We get this far, we have a list of fields
          #key = "#{flowset.source_id}|#{event["source"]}|#{template.template_id}"
          if metadata != nil
            key = "#{flowset.source_id}|#{template.template_id}|#{metadata["host"]}|#{metadata["port"]}"
          else
            key = "#{flowset.source_id}|#{template.template_id}"
          end
          # Prevent netflow_templates array from being concurrently modified
          @decode_mutex_netflow.synchronize do
            @netflow_templates[key, @cache_ttl] = BinData::Struct.new(:endian => :big, :fields => fields)
            @logger.debug("Received template #{template.template_id} with fields #{fields.inspect}")
            @logger.debug("Received template #{template.template_id} of size #{template_length} bytes. Representing in #{@netflow_templates[key].num_bytes} BinData bytes")
            if template_length != @netflow_templates[key].num_bytes
              @logger.warn("Received template #{template.template_id} of size #{template_length} bytes doesn't match BinData representation we built (#{@netflow_templates[key].num_bytes} bytes)")
            end
            # Purge any expired templates
            @netflow_templates.cleanup!
            if @cache_save_path
              @netflow_templates_cache[key] = fields
              save_templates_cache(@netflow_templates_cache, "#{@cache_save_path}/netflow_templates.cache")
            end
          end
        end
      end
    when 256..65535
      # Data flowset
      #key = "#{flowset.source_id}|#{event["source"]}|#{record.flowset_id}"
      @logger.debug? and @logger.debug("Start processing data flowset #{record.flowset_id}")
      if metadata != nil
        key = "#{flowset.source_id}|#{record.flowset_id}|#{metadata["host"]}|#{metadata["port"]}"
      else
        key = "#{flowset.source_id}|#{record.flowset_id}"
      end

      template = @decode_mutex_netflow.synchronize { @netflow_templates[key] }

      if !template
        @logger.warn("Can't (yet) decode flowset id #{record.flowset_id} from source id #{flowset.source_id}, because no template to decode it with has been received. This message will usually go away after 1 minute.")
        return events
      end

      length = record.flowset_length - 4

      # Template shouldn't be longer than the record 
      # As fas as padding is concerned, the RFC defines a SHOULD for 4-word alignment
      # so we won't complain about that.
      if template.num_bytes != nil
        if template.num_bytes > length
          @logger.warn("Template length exceeds flowset length, skipping", :template_id => record.flowset_id, :template_length => template.num_bytes, :record_length => length)
          return events
        end
      end

      array = BinData::Array.new(:type => template, :initial_length => length / template.num_bytes)
      records = array.read(record.flowset_data)

      flowcounter = 1
      records.each do |r|
        @logger.debug? and @logger.debug("Start processing flow #{flowcounter} from data flowset id #{record.flowset_id}")
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
        flowcounter += 1
      end
    else
      @logger.warn("Unsupported flowset id #{record.flowset_id}")
    end

    events
  rescue BinData::ValidityError, IOError => e
    @logger.warn("Invalid netflow packet received (#{e})")
  end

  def decode_ipfix(flowset, record)
    events = []

    case record.flowset_id
    when 2..3
      record.flowset_data.templates.each do |template|
        catch (:field) do
          fields = []
          # Template flowset (2) or Options template flowset (3) ?
          template_fields = (record.flowset_id == 2) ? template.record_fields : (template.scope_fields.to_ary + template.option_fields.to_ary)
          template_fields.each do |field|
            field_type = field.field_type
            field_length = field.field_length
            enterprise_id = field.enterprise ? field.enterprise_id : 0

            entry = ipfix_field_for(field_type, enterprise_id, field.field_length)
            throw :field unless entry
            fields += entry
          end
          # FIXME Source IP address required in key
          key = "#{flowset.observation_domain_id}|#{template.template_id}"
          # Prevent ipfix_templates array from being concurrently modified
          @decode_mutex_ipfix.synchronize do
            @ipfix_templates[key, @cache_ttl] = BinData::Struct.new(:endian => :big, :fields => fields)
            # Purge any expired templates
            @ipfix_templates.cleanup!
            if @cache_save_path
              @ipfix_templates_cache[key] = fields
              save_templates_cache(@ipfix_templates_cache, "#{@cache_save_path}/ipfix_templates.cache")
            end
          end
        end
      end
    when 256..65535
      # Data flowset
      key = "#{flowset.observation_domain_id}|#{record.flowset_id}"
      if @ipfix_templates[key] != nil
        template = @ipfix_templates[key]
      else
        @logger.warn("Can't (yet) decode flowset id #{record.flowset_id} from observation domain id #{flowset.observation_domain_id}, because no template to decode it with has been received. This message will usually go away after 1 minute.")
        return events
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

        if @include_flowset_id
          event[@target][FLOWSET_ID] = record.flowset_id.snapshot
        end

        r.each_pair do |k, v|
          case k.to_s
          when /^flow(?:Start|End)Seconds$/
            event[@target][k.to_s] = LogStash::Timestamp.at(v.snapshot).to_iso8601
          when /^flow(?:Start|End)(Milli|Micro|Nano)seconds$/
            case $1
            when 'Milli'
              event[@target][k.to_s] = LogStash::Timestamp.at(v.snapshot.to_f / 1_000).to_iso8601
            when 'Micro', 'Nano'
              # For now we'll stick to assuming ntp timestamps,
              # Netscaler implementation may be buggy though:
              # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=11047
              # This only affects the fraction though
              ntp_seconds = (v.snapshot >> 32) & 0xFFFFFFFF
              ntp_fraction = (v.snapshot & 0xFFFFFFFF).to_f / 2**32
              event[@target][k.to_s] = LogStash::Timestamp.at(Time.utc(1900,1,1).to_i + ntp_seconds, ntp_fraction * 1000000).to_iso8601
            end
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
  rescue BinData::ValidityError => e
    @logger.warn("Invalid IPFIX packet received (#{e})")
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

  def load_templates_cache(file_path)
    templates_cache = {}
    begin
      @logger.debug? and @logger.debug("Loading templates from template cache #{file_path}")
      file_data = @file_cache_mutex.synchronize { File.read(file_path)}
      templates_cache = JSON.parse(file_data)
    rescue Exception => e
      raise "#{self.class.name}: templates cache file could not be read @ (#{file_path}: #{e.class.name} #{e.message})"
    end

    templates_cache
  end

  def save_templates_cache(templates_cache, file_path)
    begin
      @logger.debug? and @logger.debug("Writing templates to template cache #{file_path}")
      @file_cache_mutex.synchronize do
        File.open(file_path, 'w') {|file| file.write templates_cache.to_json }
      end
    rescue Exception => e
      raise "#{self.class.name}: saving templates cache file failed (#{file_path}) with error #{e}"
    end
  end

  def uint_field(length, default)
    # If length is 4, return :uint32, etc. and use default if length is 0
    ("uint" + (((length > 0) ? length : default) * 8).to_s).to_sym
  end # def uint_field

  def skip_field(field, type, length)
    if length == 65535
      field[0] = :VarSkip
    else
      field += [nil, {:length => length.to_i}]
    end

    field
  end # def skip_field

  def string_field(field, type, length)
    if length == 65535
      field[0] = :VarString
    else
      field[0] = :string
      field += [{ :length => length.to_i, :trim_padding => true }]
    end

    field
  end # def string_field

  def netflow_field_for(type, length, template_id)
    if @netflow_fields.include?(type)
      field = @netflow_fields[type].clone
      if field.is_a?(Array)

        field[0] = uint_field(length, field[0]) if field[0].is_a?(Integer)

        # Small bit of fixup for:
        # - skip or string field types where the length is dynamic
	# - uint(8|16|24|32} where we use the length as specified by the
	#   template instead of the YAML (e.g. ipv6_flow_label is 3 bytes in
	#   the YAML and Cisco doc, but Cisco ASR9k sends 4 bytes)
	# - application_id where we use the length as specified by the 
	#   template and map it to custom types for handling.
	#   
	case field[0]
        when :uint8
          field[0] = uint_field(length, field[0])
        when :uint16
          field[0] = uint_field(length, field[0])
        when :uint24
          field[0] = uint_field(length, field[0])
        when :uint32
          field[0] = uint_field(length, field[0])
        when :application_id
          case length
          when 2
            field[0] = :Application_Id16
          when 3
            field[0] = :Application_Id24
          when 4
            field[0] = :Application_Id32
          when 5
            field[0] = :Application_Id40
          when 8
            field[0] = :Application_Id64
          when 9
            field[0] = :Application_Id72
          else
            @logger.warn("Unsupported application_id length encountered, skipping", :field => field, :length => length)
            nil
          end      
        when :skip
          field += [nil, {:length => length.to_i}]
        when :string
          field += [{:length => length.to_i, :trim_padding => true}]
        end

        @logger.debug? and @logger.debug("Field definition complete for template #{template_id}", :field => field)

        [field]
      else
        @logger.warn("Definition should be an array", :field => field)
        nil
      end
    else
      @logger.warn("Unsupported field in template #{template_id}", :type => type, :length => length)
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
        field = skip_field(field, type, length.to_i)
      when :string
        field = string_field(field, type, length.to_i)
      when :octetarray
        field[0] = :OctetArray
        field += [{:initial_length => length.to_i}]
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
