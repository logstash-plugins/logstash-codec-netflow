# Netflow v9 compliance

The level of RFC compliance reached for collector-relevant requirements:

| RFC       | Level                                        |
|-----------|----------------------------------------------|
| RFC 3954  | 100% of RFC "MUST" requirements implemented  |
| RFC 3954  | 0% of RFC "SHOULD" requirements implemented  |  
| RFC 3954  | 83% of IEs 1-127 supported                   |
| RFC 3954  | 10% of IEs 127-32768 supported               |

## RFC 3954 collector compliance summary

Summary of collector-relevant requirements implemented versus the total collector-relevant requirements:

| Chapter                                      |MUST |SHOULD| MAY| 
|----------------------------------------------|-----|-----|-----|
| 1. Introduction                              |     |     |     |
| 2. Terminology                               |     |     |     |
| 3. NetFlow High-Level Picture on the Exporter|     |     |     |
| 4. Packet layout                             |     |     |     |
| 5. Export packet format                      | 1/1 | 0/2 |     |
| 6. Options                                   | 1/1 |     |     |
| 7. Template management                       | 3/3 |     |     |
| 8. Field type definitions                    |     |     |     |
| 9. The collector side                        | 5/5 | 0/3 |     |
| 10. Security considerations                  |     |     |     |

## RFC 3954 collector compliance details

The tables below detail the collector-relevant requirements, and whether or not they are implemented:

### 5. Export packet format

| Requirement                           |MUST |SHOULD| MAY| 
|---------------------------------------|-----|-----|-----|
| 5.1 Incremental sequence counter of all Export Packets sent from the current Observation Domain by the Exporter.  This value MUST be cumulative, and SHOULD be used by the Collector to identify whether any Export Packets have been missed. | | NO |  |
| 5.1 NetFlow Collectors SHOULD use the combination of the source IP  address and the Source ID field to separate different export streams originating from the same Exporter. | | NO | |
| 5.3 The Collector MUST use the FlowSet ID to find the corresponding Template Record and decode the Flow Records from the FlowSet. | YES | | |

### 6. Options

| Requirement                           |MUST |SHOULD| MAY| 
|---------------------------------------|-----|-----|-----|
| 6.2 The Collector MUST use the FlowSet ID to map the appropriate type and length to any field values that follow. | YES | | |

### 7. Template management

| Requirement                           |MUST |SHOULD| MAY| 
|---------------------------------------|-----|-----|-----|
| 7. the NetFlow Collector MUST store the Template Record to interpret the corresponding Flow Data Records that are received in subsequent data packets. | YES | | |
| 7.  A NetFlow Collector that receives Export Packets from several Observation Domains from the same Exporter MUST be aware that the uniqueness of the Template ID is not guaranteed across Observation Domains. | YES | | | 
| 7.  If a Collector should receive a new definition for an already existing Template ID, it MUST discard the previous template definition and use the new one. | YES | | |

### 9. The collector side

| Requirement                           |MUST |SHOULD| MAY| 
|---------------------------------------|-----|-----|-----|
| 9. If the Template Records have not been received at the time Flow Data Records (or Options Data Records) are received, the Collector SHOULD store the Flow Data Records (or Options Data Records) and decode them after the Template Records are received. | | NO | |
| 9. A Collector device MUST NOT assume that the Data FlowSet and the associated Template FlowSet (or Options Template FlowSet) are exported in the same Export Packet. | YES | | | 
| 9. The Collector MUST NOT assume that one and only one Template FlowSet is present in an Export Packet. | YES | | | 
| 9. The Collector MUST NOT attempt to decode the Flow or Options Data Records with an expired Template. | YES | | | 
| 9. At any given time the Collector SHOULD maintain the following for all the current Template Records and Options Template Records: Exporter, Observation Domain, Template ID, Template Definition, Last Received. | | NO | |
| 9. In the event of a clock configuration change on the Exporter, the  Collector SHOULD discard all Template Records and Options Template  Records associated with that Exporter, in order for Collector to learn the new set of fields: Exporter, Observation Domain, Template ID, Template Definition, Last Received. | | NO | |
| 9. If the Collector receives a new Template Record (for example, in the case of an Exporter restart) it MUST immediately override the existing Template Record. | YES | | |
| 9. Finally, note that the Collector MUST accept padding in the Data  FlowSet and Options Template FlowSet, which means for the Flow Data Records, the Options Data Records and the Template Records. | YES | | |



## RFC 3954 Information Elements support details

From the IEs 1-127, these are not yet supported:

|id | name                
|---|--------------
|70 |MPLS_LABEL_1 
|71 |MPLS_LABEL_2 
|72 |MPLS_LABEL_3 
|73 |MPLS_LABEL_4 
|74 |MPLS_LABEL_5 
|75 |MPLS_LABEL_6 
|76 |MPLS_LABEL_7 
|77 |MPLS_LABEL_8 
|78 |MPLS_LABEL_9
|79 |MPLS_LABEL_10  
|90 | MPLS PAL RD
|91 | MPLS PREFIX LEN
|92 | SRC TRAFFIC INDEX
|93 | DST TRAFFIC INDEX
|95 | APPLICATION TAG
|99 | replication factor
|102| layer2packetSectionOffset
|103| layer2packetSectionSize
|104| layer2packetSectionData

From the IEs 128-, these are not yet supported:

|id | name         |data type       
|---|--------------|-----
|128|bgpNextAdjacentAsNumber|unsigned32
|129|bgpPrevAdjacentAsNumber|unsigned32
|130|exporterIPv4Address|ipv4Address
|131|exporterIPv6Address|ipv6Address
|132|droppedOctetDeltaCount|unsigned64
|133|droppedPacketDeltaCount|unsigned64
|134|droppedOctetTotalCount|unsigned64
|135|droppedPacketTotalCount|unsigned64
|137|commonPropertiesId|unsigned64
|138|observationPointId|unsigned64
|139|icmpTypeCodeIPv6|unsigned16
|140|mplsTopLabelIPv6Address|ipv6Address
|141|lineCardId|unsigned32
|142|portId|unsigned32
|143|meteringProcessId|unsigned32
|144|exportingProcessId|unsigned32
|145|templateId|unsigned16
|146|wlanChannelId|unsigned8
|149|observationDomainId|unsigned32
|150|flowStartSeconds|dateTimeSeconds
|151|flowEndSeconds|dateTimeSeconds
|153|flowEndMilliseconds|dateTimeMilliseconds
|154|flowStartMicroseconds|dateTimeMicroseconds
|155|flowEndMicroseconds|dateTimeMicroseconds
|156|flowStartNanoseconds|dateTimeNanoseconds
|157|flowEndNanoseconds|dateTimeNanoseconds
|158|flowStartDeltaMicroseconds|unsigned32
|159|flowEndDeltaMicroseconds|unsigned32
|160|systemInitTimeMilliseconds|dateTimeMilliseconds
|161|flowDurationMilliseconds|unsigned32
|162|flowDurationMicroseconds|unsigned32
|163|observedFlowTotalCount|unsigned64
|164|ignoredPacketTotalCount|unsigned64
|165|ignoredOctetTotalCount|unsigned64
|166|notSentFlowTotalCount|unsigned64
|167|notSentPacketTotalCount|unsigned64
|168|notSentOctetTotalCount|unsigned64
|169|destinationIPv6Prefix|ipv6Address
|170|sourceIPv6Prefix|ipv6Address
|171|postOctetTotalCount|unsigned64
|172|postPacketTotalCount|unsigned64
|173|flowKeyIndicator|unsigned64
|174|postMCastPacketTotalCount|unsigned64
|175|postMCastOctetTotalCount|unsigned64
|184|tcpSequenceNumber|unsigned32
|185|tcpAcknowledgementNumber|unsigned32
|186|tcpWindowSize|unsigned16
|187|tcpUrgentPointer|unsigned16
|188|tcpHeaderLength|unsigned8
|189|ipHeaderLength|unsigned8
|190|totalLengthIPv4|unsigned16
|191|payloadLengthIPv6|unsigned16
|192|ipTTL|unsigned8
|193|nextHeaderIPv6|unsigned8
|196|ipPrecedence|unsigned8
|197|fragmentFlags|unsigned8
|198|octetDeltaSumOfSquares|unsigned64
|199|octetTotalSumOfSquares|unsigned64
|200|mplsTopLabelTTL|unsigned8
|202|mplsLabelStackDepth|unsigned32
|203|mplsTopLabelExp|unsigned8
|204|ipPayloadLength|unsigned32
|205|udpMessageLength|unsigned16
|206|isMulticast|unsigned8
|207|ipv4IHL|unsigned8
|208|ipv4Options|unsigned32
|209|tcpOptions|unsigned64
|210|paddingOctets|octetArray
|211|collectorIPv4Address|ipv4Address
|212|collectorIPv6Address|ipv6Address
|213|exportInterface|unsigned32
|214|exportProtocolVersion|unsigned8
|215|exportTransportProtocol|unsigned8
|216|collectorTransportPort|unsigned16
|217|exporterTransportPort|unsigned16
|218|tcpSynTotalCount|unsigned64
|219|tcpFinTotalCount|unsigned64
|220|tcpRstTotalCount|unsigned64
|221|tcpPshTotalCount|unsigned64
|222|tcpAckTotalCount|unsigned64
|223|tcpUrgTotalCount|unsigned64
|224|ipTotalLength|unsigned64
|229|natOriginatingAddressRealm|unsigned8
|230|natEvent|unsigned8
|237|postMplsTopLabelExp|unsigned8
|238|tcpWindowScale|unsigned16
|239|biflowDirection|unsigned8
|240|ethernetHeaderLength|unsigned8
|241|ethernetPayloadLength|unsigned16
|242|ethernetTotalLength|unsigned16
|243|dot1qVlanId|unsigned16
|244|dot1qPriority|unsigned8
|245|dot1qCustomerVlanId|unsigned16
|246|dot1qCustomerPriority|unsigned8
|247|metroEvcId|string
|248|metroEvcType|unsigned8
|249|pseudoWireId|unsigned32
|250|pseudoWireType|unsigned16
|251|pseudoWireControlWord|unsigned32
|252|ingressPhysicalInterface|unsigned32
|253|egressPhysicalInterface|unsigned32
|254|postDot1qVlanId|unsigned16
|255|postDot1qCustomerVlanId|unsigned16
|256|ethernetType|unsigned16
|257|postIpPrecedence|unsigned8
|258|collectionTimeMilliseconds|dateTimeMilliseconds
|259|exportSctpStreamId|unsigned16
|260|maxExportSeconds|dateTimeSeconds
|261|maxFlowEndSeconds|dateTimeSeconds
|262|messageMD5Checksum|octetArray
|263|messageScope|unsigned8
|264|minExportSeconds|dateTimeSeconds
|265|minFlowStartSeconds|dateTimeSeconds
|266|opaqueOctets|octetArray
|267|sessionScope|unsigned8
|268|maxFlowEndMicroseconds|dateTimeMicroseconds
|269|maxFlowEndMilliseconds|dateTimeMilliseconds
|270|maxFlowEndNanoseconds|dateTimeNanoseconds
|271|minFlowStartMicroseconds|dateTimeMicroseconds
|272|minFlowStartMilliseconds|dateTimeMilliseconds
|273|minFlowStartNanoseconds|dateTimeNanoseconds
|274|collectorCertificate|octetArray
|275|exporterCertificate|octetArray
|276|dataRecordsReliability|boolean
|277|observationPointType|unsigned8
|278|newConnectionDeltaCount|unsigned32
|279|connectionSumDurationSeconds|unsigned64
|280|connectionTransactionId|unsigned64
|283|natPoolId|unsigned32
|284|natPoolName|string
|285|anonymizationFlags|unsigned16
|286|anonymizationTechnique|unsigned16
|287|informationElementIndex|unsigned16
|288|p2pTechnology|string
|289|tunnelTechnology|string
|290|encryptedTechnology|string
|291|basicList|basicList
|292|subTemplateList|subTemplateList
|293|subTemplateMultiList|subTemplateMultiList
|294|bgpValidityState|unsigned8
|295|IPSecSPI|unsigned32
|296|greKey|unsigned32
|297|natType|unsigned8
|300|observationDomainName|string
|301|selectionSequenceId|unsigned64
|302|selectorId|unsigned64
|303|informationElementId|unsigned16
|304|selectorAlgorithm|unsigned16
|305|samplingPacketInterval|unsigned32
|306|samplingPacketSpace|unsigned32
|307|samplingTimeInterval|unsigned32
|308|samplingTimeSpace|unsigned32
|309|samplingSize|unsigned32
|310|samplingPopulation|unsigned32
|311|samplingProbability|float64
|312|dataLinkFrameSize|unsigned16
|313|ipHeaderPacketSection|octetArray
|314|ipPayloadPacketSection|octetArray
|315|dataLinkFrameSection|octetArray
|316|mplsLabelStackSection|octetArray
|317|mplsPayloadPacketSection|octetArray
|318|selectorIdTotalPktsObserved|unsigned64
|319|selectorIdTotalPktsSelected|unsigned64
|320|absoluteError|float64
|321|relativeError|float64
|322|observationTimeSeconds|dateTimeSeconds
|324|observationTimeMicroseconds|dateTimeMicroseconds
|325|observationTimeNanoseconds|dateTimeNanoseconds
|326|digestHashValue|unsigned64
|327|hashIPPayloadOffset|unsigned64
|328|hashIPPayloadSize|unsigned64
|329|hashOutputRangeMin|unsigned64
|330|hashOutputRangeMax|unsigned64
|331|hashSelectedRangeMin|unsigned64
|332|hashSelectedRangeMax|unsigned64
|333|hashDigestOutput|boolean
|334|hashInitialiserValue|unsigned64
|335|selectorName|string
|336|upperCILimit|float64
|337|lowerCILimit|float64
|338|confidenceLevel|float64
|339|informationElementDataType|unsigned8
|340|informationElementDescription|string
|341|informationElementName|string
|342|informationElementRangeBegin|unsigned64
|343|informationElementRangeEnd|unsigned64
|344|informationElementSemantics|unsigned8
|345|informationElementUnits|unsigned16
|347|virtualStationInterfaceId|octetArray
|348|virtualStationInterfaceName|string
|349|virtualStationUUID|octetArray
|350|virtualStationName|string
|351|layer2SegmentId|unsigned64
|352|layer2OctetDeltaCount|unsigned64
|353|layer2OctetTotalCount|unsigned64
|354|ingressUnicastPacketTotalCount|unsigned64
|355|ingressMulticastPacketTotalCount|unsigned64
|356|ingressBroadcastPacketTotalCount|unsigned64
|357|egressUnicastPacketTotalCount|unsigned64
|358|egressBroadcastPacketTotalCount|unsigned64
|359|monitoringIntervalStartMilliSeconds|dateTimeMilliseconds
|360|monitoringIntervalEndMilliSeconds|dateTimeMilliseconds
|363|portRangeStepSize|unsigned16
|364|portRangeNumPorts|unsigned16
|368|ingressInterfaceType|unsigned32
|369|egressInterfaceType|unsigned32
|370|rtpSequenceNumber|unsigned16
|371|userName|string
|372|applicationCategoryName|string
|373|applicationSubCategoryName|string
|374|applicationGroupName|string
|375|originalFlowsPresent|unsigned64
|376|originalFlowsInitiated|unsigned64
|377|originalFlowsCompleted|unsigned64
|378|distinctCountOfSourceIPAddress|unsigned64
|379|distinctCountOfDestinationIPAddress|unsigned64
|380|distinctCountOfSourceIPv4Address|unsigned32
|381|distinctCountOfDestinationIPv4Address|unsigned32
|382|distinctCountOfSourceIPv6Address|unsigned64
|383|distinctCountOfDestinationIPv6Address|unsigned64
|384|valueDistributionMethod|unsigned8
|385|rfc3550JitterMilliseconds|unsigned32
|386|rfc3550JitterMicroseconds|unsigned32
|387|rfc3550JitterNanoseconds|unsigned32
|388|dot1qDEI|boolean
|389|dot1qCustomerDEI|boolean
|390|flowSelectorAlgorithm|unsigned16
|391|flowSelectedOctetDeltaCount|unsigned64
|392|flowSelectedPacketDeltaCount|unsigned64
|393|flowSelectedFlowDeltaCount|unsigned64
|394|selectorIDTotalFlowsObserved|unsigned64
|395|selectorIDTotalFlowsSelected|unsigned64
|396|samplingFlowInterval|unsigned64
|397|samplingFlowSpacing|unsigned64
|398|flowSamplingTimeInterval|unsigned64
|399|flowSamplingTimeSpacing|unsigned64
|400|hashFlowDomain|unsigned16
|401|transportOctetDeltaCount|unsigned64
|402|transportPacketDeltaCount|unsigned64
|403|originalExporterIPv4Address|ipv4Address
|404|originalExporterIPv6Address|ipv6Address
|405|originalObservationDomainId|unsigned32
|406|intermediateProcessId|unsigned32
|407|ignoredDataRecordTotalCount|unsigned64
|408|dataLinkFrameType|unsigned16
|409|sectionOffset|unsigned16
|410|sectionExportedOctets|unsigned16
|411|dot1qServiceInstanceTag|octetArray
|412|dot1qServiceInstanceId|unsigned32
|413|dot1qServiceInstancePriority|unsigned8
|414|dot1qCustomerSourceMacAddress|macAddress
|415|dot1qCustomerDestinationMacAddress|macAddress
|416||
|417|postLayer2OctetDeltaCount|unsigned64
|418|postMCastLayer2OctetDeltaCount|unsigned64
|419||
|420|postLayer2OctetTotalCount|unsigned64
|421|postMCastLayer2OctetTotalCount|unsigned64
|422|minimumLayer2TotalLength|unsigned64
|423|maximumLayer2TotalLength|unsigned64
|424|droppedLayer2OctetDeltaCount|unsigned64
|425|droppedLayer2OctetTotalCount|unsigned64
|426|ignoredLayer2OctetTotalCount|unsigned64
|427|notSentLayer2OctetTotalCount|unsigned64
|428|layer2OctetDeltaSumOfSquares|unsigned64
|429|layer2OctetTotalSumOfSquares|unsigned64
|430|layer2FrameDeltaCount|unsigned64
|431|layer2FrameTotalCount|unsigned64
|432|pseudoWireDestinationIPv4Address|ipv4Address
|433|ignoredLayer2FrameTotalCount|unsigned64
|434|mibObjectValueInteger|signed32
|435|mibObjectValueOctetString|octetArray
|436|mibObjectValueOID|octetArray
|437|mibObjectValueBits|octetArray
|438|mibObjectValueIPAddress|ipv4Address
|439|mibObjectValueCounter|unsigned64
|440|mibObjectValueGauge|unsigned32
|441|mibObjectValueTimeTicks|unsigned32
|442|mibObjectValueUnsigned|unsigned32
|443|mibObjectValueTable|subTemplateList
|444|mibObjectValueRow|subTemplateList
|445|mibObjectIdentifier|octetArray
|446|mibSubIdentifier|unsigned32
|447|mibIndexIndicator|unsigned64
|448|mibCaptureTimeSemantics|unsigned8
|449|mibContextEngineID|octetArray
|450|mibContextName|string
|451|mibObjectName|string
|452|mibObjectDescription|string
|453|mibObjectSyntax|string
|454|mibModuleName|string
|455|mobileIMSI|string
|456|mobileMSISDN|string
|457|httpStatusCode|unsigned16
|458|sourceTransportPortsLimit|unsigned16
|459|httpRequestMethod|string
|460|httpRequestHost|string
|461|httpRequestTarget|string
|462|httpMessageVersion|string
|463|natInstanceID|unsigned32
|464|internalAddressRealm|octetArray
|465|externalAddressRealm|octetArray
|466|natQuotaExceededEvent|unsigned32
|467|natThresholdEvent|unsigned32
|468|httpUserAgent|string
|469|httpContentType|string
|470|httpReasonPhrase|string

