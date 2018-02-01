require 'benchmark'

Benchmark.bm do |x|
  x.report {
    # Implementation pre v3.11.0
    bytes=[41, 41, 41, 41, 41, 41]
    2000000.times do
      bytes.collect { |byte| 
        unless byte.nil?
          byte.to_s(16).rjust(2,'0')
        end
      }.join(":")
    end }

  x.report {
    # Implementation as of v3.11.1
    bytes='AAAAAA'
    2000000.times do
      b = bytes.unpack('H*')[0]
      b.scan(/../).collect { |byte| byte }.join(":")
    end }

  x.report {
    bytes='AAAAAA'
    2000000.times do
      b = bytes.unpack('H*')[0]
      b[0..1] + ":" + b[2..3] + ":" + b[4..5] + ":" + b[6..7] + ":" + b[8..9] + ":" + b[10..11]
    end }
end
   
#       user     system      total        real
#   8.400000   0.000000   8.400000 (  8.408549)
#  10.960000   0.000000  10.960000 ( 10.959357)
#   5.600000   0.000000   5.600000 (  5.597817)
