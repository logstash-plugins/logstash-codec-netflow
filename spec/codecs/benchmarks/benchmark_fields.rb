require 'benchmark'
require 'bindata'
require '../../../lib/logstash/codecs/netflow/util.rb'

Benchmark.bm(16) do |x|
  x.report("IP4Addr") {
    data = ["344c01f9"].pack("H*")
    200000.times do
      IP4Addr.read(data)
    end }

  x.report("IP6Addr") {
    data = ["fe80000000000000e68d8cfffe20ede6"].pack("H*")
    200000.times do
      IP6Addr.read(data)
    end }

  x.report("IP6Addr_Test") {
    data = ["fe80000000000000e68d8cfffe20ede6"].pack("H*")
    200000.times do
      IP6Addr_Test.read(data)
    end }

  x.report("MacAddr") {
    data = ["005056c00001"].pack("H*")
    200000.times do
      MacAddr.read(data)
    end }

  x.report("ACLIdASA") {
    data = ["433a1af1be9efe9600000000"].pack("H*")
    200000.times do
      ACLIdASA.read(data)
    end }

  x.report("Application_Id64") {
    data = ["140000304400003dc8"].pack("H*")
    200000.times do
      Application_Id64.read(data)
    end }

  x.report("VarString") {
    data = ["184c534e34344031302e3233312e3232332e31313300000000"].pack("H*")
    200000.times do
      VarString.read(data)
    end }

  x.report("VarString_Test") {
    data = ["184c534e34344031302e3233312e3232332e31313300000000"].pack("H*")
    200000.times do
      VarString_Test.read(data)
    end }

end

#                        user     system      total        real
# IP4Addr           24.120000   0.000000  24.120000 ( 24.123782)
# IP6Addr           37.940000   0.010000  37.950000 ( 37.950464)
# MacAddr           25.270000   0.000000  25.270000 ( 25.282082)
# ACLIdASA          24.870000   0.000000  24.870000 ( 24.882335)
# Application_Id64  41.270000   0.000000  41.270000 ( 41.305001)
# VarString         39.030000   0.000000  39.030000 ( 39.062235)



