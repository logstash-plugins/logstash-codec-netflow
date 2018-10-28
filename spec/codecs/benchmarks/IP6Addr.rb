require 'benchmark'
require 'ipaddr'
require 'bindata'

Benchmark.bm do |x|
  x.report {
    # Implementation since v0.1
    ip = 85060308944708794891899627827609206785
    2000000.times do
      IPAddr.new_ntoh((0..7).map { |i|
        (ip >> (112 - 16 * i)) & 0xffff
      }.pack('n8')).to_s
    end }

  x.report {
    # Implementation since v4.2.0
    ip = 85060308944708794891899627827609206785
    2000000.times do
      b = "%032x" % ip
      c = b[0..3] + ":" + b[4..7] + ":" + b[8..11] + ":" + b[12..15] + ":" + b[16..19] + ":" + b[20..23] + ":" + b[24..27] + ":" + b[28..31]
      IPAddr.new(c).to_s
    end }

  x.report {
    # Alternative. Loses compressed IPv6 notation
    ip = 85060308944708794891899627827609206785
    2000000.times do
      b = "%032x" % ip
      b[0..3] + ":" + b[4..7] + ":" + b[8..11] + ":" + b[12..15] + ":" + b[16..19] + ":" + b[20..23] + ":" + b[24..27] + ":" + b[28..31]
    end }

end
   
#       user     system      total        real
#  81.500000   0.000000  81.500000 ( 81.498991)
#  78.210000   0.000000  78.210000 ( 78.252662)
#  11.710000   0.010000  11.720000 ( 11.712025)

