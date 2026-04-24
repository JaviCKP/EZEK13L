# Features que usa la IA

## Resumen

La pipeline convierte logs Zeek en un vector numerico por flujo en `pipeline/build_features.py`.

Hay dos modelos y no deben usar exactamente lo mismo:

- **Baseline no supervisado (`HalfSpaceTrees`)**: debe mirar forma, ratios y comportamiento relativo. No debe depender de conteos brutos de ventana, porque eso hace que poco trafico benigno parezca raro.
- **Clasificador supervisado (`CentroidAttackClassifier`)**: puede mirar todo el vector, incluidos conteos, porque aprende familias etiquetadas de ataque.

## Familias actuales de features

### 1. Volumen y duracion por flujo

Ejemplos:

- `duration`
- `orig_bytes`
- `resp_bytes`
- `total_bytes`
- `total_pkts`
- `bytes_per_pkt`
- `orig_resp_byte_ratio`
- `log_total_bytes`
- `log_total_pkts`

Problema: los valores brutos (`total_bytes`, `orig_bytes`, etc.) pueden dominar el detector no supervisado. Por eso el baseline ahora usa preferentemente logs y ratios.

### 2. Protocolo, servicio y estado

Ejemplos:

- `proto_tcp`
- `proto_udp`
- `proto_icmp`
- `svc_http`
- `svc_dns`
- `svc_tls`
- `state_sf`
- `state_s0`
- `state_rej`

Estas features son buenas: expresan tipo de flujo y resultado de conexion.

### 3. HTTP

Ejemplos:

- `http_method_get`
- `http_method_post`
- `http_status_4xx`
- `http_status_5xx`
- `http_uri_len_max`
- `http_uri_entropy_max`
- `http_query_len_max`
- `http_param_count_max`
- `http_special_char_count_max`
- `http_percent_encoding_count_max`
- `http_request_body_len`
- `http_response_body_len`

Estas ayudan a SQL injection, brute force HTTP y exfil por HTTP.

### 4. DNS

Ejemplos:

- `dns_query_len_max`
- `dns_query_entropy_max`
- `dns_label_count_max`
- `dns_answer_count_max`
- `dns_nxdomain`
- `dns_rejected`

Estas ayudan a detectar DNS exfiltration.

### 5. TLS

Ejemplos:

- `tls_tx_count`
- `tls_sni_len_max`
- `tls_established`
- `tls_resumed`
- `tls_ja3_present`
- `tls_version_tlsv12`
- `tls_version_tlsv13`

Ahora son basicas, pero suficientes para una PoC.

### 6. Ventanas temporales 60s / 300s

Antes habia muchos conteos brutos:

- `src_conn_count_60s`
- `src_unique_dst_ports_60s`
- `src_total_bytes_300s`
- `pair_http_count_60s`

Esto ayuda a scans y bursts, pero tambien crea falsos positivos cuando el trafico benigno es escaso.

He anadido features relativas:

- `src_failed_conn_ratio_60s`
- `src_unique_dst_ip_ratio_60s`
- `src_unique_dst_port_ratio_60s`
- `src_bytes_per_conn_60s`
- `dst_unique_src_ip_ratio_60s`
- `src_http_post_ratio_60s`
- `src_http_post_error_ratio_60s`
- `pair_http_post_error_ratio_60s`

Y equivalentes a 300s.

Estas son mejores porque describen comportamiento:

- "de mis conexiones, que porcentaje falla";
- "cuantos puertos distintos por conexion toca este origen";
- "cuantos POST fallidos por POST";
- "cuantos bytes por conexion".

## Cambio aplicado al baseline

Nuevo archivo:

- `pipeline/feature_selection.py`

El detector no supervisado ya no usa:

- puertos como numero ordinal (`dst_port`);
- codigos categoricos numericos (`http_status_code`, `dns_qtype`, `dns_rcode`);
- conteos brutos de ventana;
- bytes/paquetes brutos de ventana;
- `bytes_per_second` y `pkts_per_second`, que son muy sensibles a duraciones sinteticas pequenas.

Si usa:

- flags de protocolo/servicio/estado;
- ratios;
- logs;
- entropia;
- shape HTTP/DNS/TLS;
- ratios de ventana.

## Que espero que mejore

1. Menos falsos positivos en `Control benigno`.
2. Mejor separacion entre "red quieta" y "ataque".
3. Menos dependencia de densidad exacta de entrenamiento.
4. Clasificador mas fuerte porque ahora recibe nuevas features de ratio/burst.

## Como medirlo

Cuando Docker funcione:

```powershell
.\scripts\poc-train.ps1
.\scripts\validate-poc.ps1 -RequireMl -KeepArtifacts
```

Mirar:

- `Control benigno`: `Anomalias ML = 0`, `Clasificador = 0`.
- Ataques: `Prediccion IA` correcta y confianza alta.
- Si un ataque solo sale por Suricata/Expert, revisar si faltan features para esa familia.
