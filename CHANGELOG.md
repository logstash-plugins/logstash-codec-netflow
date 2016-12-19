## 3.1.5

  - Add Netflow v9/v10 template caching, configurable TTL
  - Add option for including flowset_id for Netflow v10
  - Refactor/simplify Netflow v9/v10 templates processing
  - Add variable length field support
  - Add OctetArray support
  - Add Citrix Netscaler (IPFIX) support
  - Add spec tests and anonymized test data for all of the above

## 3.1.4

  - Added support for MPLS labels
  - Added support for decoding forwarded status field (Netflow 9)

## 3.1.3

  - Confirmed support and tests added for 4 Netflow/IPFIX exporters

## 3.1.2

  - Relax constraint on logstash-core-plugin-api to >= 1.60 <= 2.99

## 3.1.1

  - Small update due to breaking change in BinData gem (issue #41)

## 3.1.0

  - Added IPFIX support

## 3.0.1

  - Republish all the gems under jruby.

## 3.0.0

  - Update the plugin to the version 2.0 of the plugin api, this change is required for Logstash 5.0 compatibility. See https://github.com/elastic/logstash/issues/5141
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

