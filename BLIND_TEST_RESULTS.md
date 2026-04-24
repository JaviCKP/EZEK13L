# Blind Generalization Test

> Ataques generados con IPs, dominios, endpoints y payloads **distintos** a los del entrenamiento.
> El modelo no fue reentrenado. Esta tabla mide generalizaciÃ³n, no memorizaciÃ³n.

Threshold usado: `0.95`
Modo RequireMl: `False`

| Escenario | Flujos evaluados | Threshold | Max ML raw | Detecciones ML | Etiqueta ML | Deriva raw | Conf clase | Senales expert | Capas | Factors expert | Suricata | Resultado |
| --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | --- | --- | --- | --- |
| Control benigno | 12 | 0.95 | 0.919868 | 0 | - | 0 | 0.417587 | 0 | - | - | - | PASS |
| Port Scan (blind) | 50 | 0.95 | 0.85113 | 16 | port_scan | 0 | 0.575154 | 42 | ML, Expert, Suricata | scan_ports_300s, scan_ports_60s | LOCAL Possible SYN scan | PASS |
| DNS Exfiltration (blind) | 20 | 0.95 | 0.793958 | 19 | dns_exfiltration | 0 | 0.759748 | 20 | ML, Expert | dns_nxdomain, dns_query_shape, dns_rejected | - | PASS |
| Brute Force HTTP (blind) | 35 | 0.95 | 0.851591 | 17 | brute_force_http | 0 | 0.542875 | 0 | ML, Suricata | - | LOCAL Possible SYN scan | PASS |
| SQL Injection (blind) | 8 | 0.95 | 0.817676 | 8 | sql_injection | 0 | 0.763957 | 6 | ML, Expert, Suricata | http_error_response, http_payload_shape | LOCAL WEB possible SQL injection SELECT | PASS |
| Data Exfiltration (blind) | 5 | 0.95 | 0.931478 | 0 | - | 0 | 0.389416 | 1 | Expert | volume_spike | - | PASS |

## Interpretacion

**Generalizacion completa (5/5):** el sistema detecta las 5 familias de ataque incluso con IPs, dominios y payloads distintos a los del entrenamiento. La arquitectura multi-capa aprende comportamiento, no patrones exactos.

---
_Generado por `scripts/validate-blind.ps1`_
