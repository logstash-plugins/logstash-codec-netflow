# encoding: utf-8
require 'benchmark'
require 'bindata'


Benchmark.bm do |x|
  x.report {
    # Original IPFIX version, simplified
    k = 'flowStartMilliseconds'
    data = '1000'
    v = BinData::String.new(:read_length => 4)
    v.read(data)
    2000000.times do
       case k.to_s 
       when /^flow(?:Start|End)Seconds$/ 
         event = 'blah'
       when /^flow(?:Start|End)(Milli|Micro|Nano)seconds$/ 
         case $1 
         when 'Milli' 
           event = v.snapshot.to_f / 1_000
         end 
       end
    end }

  x.report {
    # Verion that omits v.snapshot, simplified
    k = 'flowStartMilliseconds'
    data = '1000'
    v = BinData::String.new(:read_length => 4)
    v.read(data)
    2000000.times do
       case k.to_s 
       when /^flow(?:Start|End)Seconds$/ 
         event = 'blah'
       when /^flow(?:Start|End)(Milli|Micro|Nano)seconds$/ 
         case $1 
         when 'Milli' 
           event = data.to_f / 1_000
         end 
       end
    end }

  x.report {
    # Original Netflow9 version, simplified
    class MockFlowset < BinData::Record
      endian :little
      uint8 :uptime
      uint8 :unix_sec
    end
    SWITCHED = /_switched$/
    data1 = 'AB'
    flowset = MockFlowset.read(data1)
    k = 'first_switched'
    v = 20
    2000000.times do
      case k.to_s
      when SWITCHED
        millis = flowset.uptime - v
        seconds = flowset.unix_sec - (millis / 1000)
        # v9 did away with the nanosecs field
        micros = 1000000 - (millis % 1000)
        event = v
      else
        event = 'blah'
      end
    end }

end

#       user     system      total        real
#   4.730000   0.000000   4.730000 (  4.731333)
#   2.400000   0.000000   2.400000 (  2.401072)
#   2.750000   0.000000   2.750000 (  2.747525)
