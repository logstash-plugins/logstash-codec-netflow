# IPFIX RFC compliance

Summary:

| RFC       | Level |
|-----------|-------|
| RFC 7011  | 47% of RFC "MUST" items implemented |  
| RFC 7012  | 56% of data types implemented

## RFC 7011 Collector compliance

| Chapter | MUST | SHOULD | MAY | 
|---------|------|--------|-----|
| 1. Introduction                       |     |     |     |
| 1. Terminology                        |     |     |     |
| 3. IPFIX message format               | 2/2 | 0/2 |     |
| 4. Specific reporting requirements    | 0/1 |     |     |
| 5. Timing considerations              |     | 0/2 |     |
| 6. Linkage with the Information Model |     | 0/1 |     |
| 7. Variable Length IE                 |     |     |     |
| 8. Template management                | 4/8 | 1/5 | 1/2 |
| 9. The collecting process's side      | 4/5 | 1/3 | 0/4 |
| 10. Transport protocol                | 5/8 | 1/3 | 3/3 |
| 11. Security considerations           | 0/8 | 1/5 | 2/3 |
| 12. Management considerations         |     |     |     |
| 13. IANA considerations               |     |     |     |

## RFC7012 Information Elements data type decoding support

| IE data type          | Support | Variable Length support |
|-----------------------|---------|-------------------------|
| octetArray            | Yes     | Yes |
| unsigned8             | Yes     |     |
| unsigned16            | Yes     |     |
| unsigned32            | Yes     |     |
| unsigned64            | Yes     |     |
| signed8               | No      |     |
| signed16              | No      |     |
| signed32              | No      |     |
| signed64              | No      |     |
| float32               | No      |     |
| float64               | No      |     |
| boolean               | No      |     |
| macAddress            | Yes     |     |
| string                | Yes     | Yes |
| dateTimeSeconds       | Yes     |     |
| dateTimeMilliseconds  | Yes     |     |
| dateTimeMicroseconds  | Yes     |     |
| dateTimeNanoseconds   | Yes     |     |
| ipv4Address           | Yes     |     |
| ipv6Address           | Yes     |     |
| basicList             | No      |     |
| subTemplateList       | No      |     |
| subTemplateMultiList  | No      |     |
