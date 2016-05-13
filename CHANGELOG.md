## 2.1.0

  - Added IPFIX support
  - Fixed exception if Netflow data contains MAC addresses (issue #26, issue #34)
  - Fixed exceptions when receiving invalid Netflow v5 and v9 data (issue #17, issue 18)
  - Fixed decoding Netflow templates from multiple (non-identical) exporters
  - Add support for Cisco ASA fields
  - Add support for Netflow 9 options template with scope fields 

# 2.0.5

  - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash

# 2.0.4

  - New dependency requirements for logstash-core for the 5.0 release

## 2.0.3

 - Fixed JSON compare flaw in specs

## 2.0.0

 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully,
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0

