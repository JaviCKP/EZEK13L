# Validacion PoC

Threshold usado: `0.95`
Modo RequireMl: `True`

| Escenario | Flujos evaluados | Threshold | Max ML raw | Detecciones ML | Etiqueta ML | Deriva raw | Conf clase | Senales expert | Capas | Factors expert | Suricata | Resultado |
| --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | --- | --- | --- | --- |
| Control benigno | 12 | 0.95 | 0.919868 | 0 | - | 0 | 0.417587 | 0 | - | - | - | PASS |
| Port Scan | 50 | 0.95 | 0.85113 | 46 | port_scan | 0 | 0.621461 | 42 | ML, Expert, Suricata | scan_ports_300s, scan_ports_60s | LOCAL Possible SYN scan | PASS |
| DNS Exfiltration | 24 | 0.95 | 0.799703 | 23 | dns_exfiltration | 0 | 0.817832 | 24 | ML, Expert | dns_nxdomain, dns_query_shape, dns_rejected | - | PASS |
| Brute Force HTTP | 40 | 0.95 | 0.836197 | 25 | brute_force_http | 0 | 0.579463 | 0 | ML, Suricata | - | LOCAL Possible SYN scan | LOCAL WEB login POST burst | PASS |
| SQL Injection | 8 | 0.95 | 0.796489 | 7 | sql_injection | 0 | 0.818878 | 2 | ML, Expert, Suricata | http_payload_shape | LOCAL WEB possible SQL injection information_schema | LOCAL WEB possible SQL injection SELECT | LOCAL WEB possible SQL injection time delay | LOCAL WEB possible SQL injection UNION | PASS |
| Data Exfiltration | 1 | 0.95 | 0.752291 | 0 | - | 0 | 0.380669 | 1 | Expert | volume_spike | - | FAIL |

Conclusion: hay fallos en la matriz minima de la PoC.
