## 3.11.2

  - Further improved decoding performance of ASA ACL ids
  - Further improved decoding performance of MAC addresses
  - Improved decoding performance of IPv4 addresses

## 3.11.1

  - Improved decoding performance of ASA ACL ids
  - Improved decoding performance of mac addresses

## 3.11.0

  - Updated Netflow v9 IE coverage from 10% to 90%
  - Added support for Huawei Netstream

## 3.10.0

  - Added support for Nokia BRAS

## 3.9.1

  - Added Netflow v9 IE150 IE151, IE154, IE155

## 3.9.0

  - Added vIPtela support
  - Added fields for Cisco ASR1k

## 3.8.3

  - Fixed a race condition that could cause some errors when running in a multithreaded input

## 3.8.2

  - Fixed exceptions due to NilClass in util.rb and netflow.rb

## 3.8.1

  - Prevent Netflow and IPFIX templates from being modified concurrently
  - Improved Palo Alto support and added rspec test

## 3.8.0

  - Added initial YAF support with applabel and silk (but without DPI plugins because of complex data types)

## 3.7.1

  - Update gemspec summary
  - Added support for CISCO1941/K9 software 15.1 
  - Added undocumented Netscaler fields

## 3.7.0

  - Added support for Cisco WLC 8510 software 8.2

## 3.6.0

  - Added support for nprobe L7 DPI
  - Added support for Fortigate FortiOS 5.4.x (application_id)

## 3.5.2

  - Fix some documentation issues

## 3.5.1

  - Added test for Fortigate FortiOS 5.2 (Netflow v9)
  - Added permission check to templates cache (Issue #80)
  - Clarified confusing warning about missing templates
  - Added test for Barracuda firewall (IPFIX)

## 3.5.0

  - Added support for Cisco WLC (Netflow v9)

## 3.4.0

  - Added support for Cisco NBAR (Netflow v9)

## 3.3.0

  - Added support for Cisco ASR 9000 (Netflow v9)

## 3.2.5

  - Added support for Streamcore StreamGroomer (Netflow v9)
  - Fixed docs so they can generate

## 3.2.4

  - Fixed 0-length template field length (Netflow 9)

## 3.2.3

  - Fixed 0-length scope field length (Netflow 9, Juniper SRX)
  - Fixed JRuby 9K compatibility

## 3.2.2

  - Added support for VMware VDS IPFIX although field definitions are unknown

## 3.2.1

  - Fix/Refactor IPFIX microsecond/nanosecond interpretation (NTP Timestamp based)
  - Note a possible bug in Netscaler implementation where the fraction is proabably output as microseconds
  - Correct rspec testing for new/correct implementation of microseconds, never noticed the insane values before, mea culpa

## 3.2.0

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

