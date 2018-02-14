require 'benchmark'

Benchmark.bm do |x|
  x.report {
    # Implementation pre v3.11.0
    bytes=[41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41]
    2000000.times do
      b = bytes.collect { |byte| 
        unless byte.nil?
          byte.to_s(16).rjust(2,'0')
        end
      }.join
      b.scan(/......../).collect { |aclid| aclid }.join("-")
    end }

  x.report {
    # Implementation as of v3.11.1
    bytes='AAAAAAAAAAAA'
    2000000.times do
      b = bytes.unpack('H*')[0]
      b.scan(/......../).collect { |aclid| aclid }.join("-")
    end }

  x.report {
    # Implementation as of v3.11.2
    bytes='AAAAAAAAAAAA'
    2000000.times do
      b = bytes.unpack('H*')[0]
      b[0..7] + "-" + b[8..15] + "-" + b[16..23]
    end }
end

#       user     system      total        real
#  19.710000   0.000000  19.710000 ( 19.717288)
#   7.000000   0.000000   7.000000 (  7.003011)
#   3.500000   0.000000   3.500000 (  3.501547)
