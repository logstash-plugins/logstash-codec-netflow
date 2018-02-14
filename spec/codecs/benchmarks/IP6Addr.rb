require 'benchmark'
require 'ipaddr'

Benchmark.bm do |x|
  x.report {
    # Implementation pre v3.11.0
    ip = 85060308944708794891899627827609206785
    2000000.times do
      IPAddr.new_ntoh([ip].pack('N')).to_s
    end }

  x.report {
    # Implementation as of v3.11.2
    ip = 85060308944708794891899627827609206785
    2000000.times do
      b = "%032x" % ip
      b[0..3] + ":" + b[4..7] + ":" + b[8..11] + ":" + b[12..15] + ":" + b[16..19] + ":" + b[20..23] + ":" + b[24..27] + ":" + b[28..31]
    end }

end
   
#       user     system      total        real
#  21.800000   0.000000  21.800000 ( 21.811893)
#  11.760000   0.000000  11.760000 ( 11.768260)
