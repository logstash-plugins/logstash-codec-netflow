require 'benchmark'
require 'ipaddr'

Benchmark.bm do |x|
  x.report {
    # Implementation pre v3.11.0
    ip = 3232235521
    2000000.times do
      IPAddr.new_ntoh([ip].pack('N')).to_s
    end }

  x.report {
    # Implementation as of v3.11.2
    ip = 3232235521
    2000000.times do
      [ip].pack('N').unpack('C4').join('.')
    end }

  x.report {
    ip = 3232235521
    2000000.times do
      b = "%08x" % ip
      "%d.%d.%d.%d" % [b[0..1].to_i(16), b[2..3].to_i(16), b[4..5].to_i(16), b[6..7].to_i(16)]
    end }

end

#       user     system      total        real
#  21.330000   0.000000  21.330000 ( 21.348559)
#   4.410000   0.000000   4.410000 (  4.411973)
#   6.450000   0.000000   6.450000 (  6.446321)



