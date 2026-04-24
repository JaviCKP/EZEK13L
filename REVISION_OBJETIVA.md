# Revisión objetiva del repositorio lab-ndr

**Fecha:** 2026-04-24  
**Revisado por:** Claude Sonnet 4.6 (revisión automática completa)  
**Alcance:** Arquitectura, datos, modelo, validación, honestidad científica

---

## Veredicto general

**Es una POC bien hecha y honesta, con un defecto estructural que hay que nombrar.**

No hay trampa en el sentido clásico (no hay datos de test en el entrenamiento, no hay métricas inventadas). Pero hay un problema de fondo que no está suficientemente explicitado: el modelo aprende a detectar los ataques que genera `simulation/common.py` y luego se valida con... los mismos ataques que genera `simulation/common.py`. Eso es circular, aunque sea involuntario. Abajo el desglose completo.

---

## Lo que funciona bien

### Arquitectura multi-capa honesta

El diseño tiene tres capas independientes que se suman sin solaparse artificialmente:

1. **Suricata** (firmas clásicas): detecta SQLi, SYN scans, brute force por patrones conocidos
2. **HalfSpaceTrees** (anomalía no supervisada): detecta comportamiento estadísticamente raro vs. la línea base de red normal
3. **CentroidAttackClassifier** (clasificación supervisada): etiqueta el tipo de ataque cuando el perfil de features coincide con las familias conocidas

Además hay un cuarto componente, los **expert signals** (boosts de comportamiento), que actúan como heurísticas intermedias. Que estén separados del score del modelo es una decisión de diseño correcta.

### Anti-poisoning en el aprendizaje online

El sistema bloquea el aprendizaje cuando:
- Score supera el umbral (`.score_above_threshold`)
- Suricata ya alertó sobre esa IP/flow
- El clasificador ya etiquetó el flow como ataque
- El flow fue previamente marcado como anomalía

Esto no es trivial y está bien pensado. Es exactamente lo que fallaría en una implementación naïve.

### Feature engineering defensivo

Para el modelo no supervisado se usan **ratios** en vez de valores absolutos:
- `error_ratio_60s` en lugar de `failed_conn_count_60s`
- `unique_ip_ratio_60s` en lugar de `unique_dst_ips_60s`
- `bytes_per_conn_60s` en lugar de `total_bytes_60s`

Esta decisión evita que variaciones de volumen entre entornos revienten el modelo. Hay razonamiento real detrás, no feature engineering por defecto.

### Documentación y transparencia

- `MODEL_CARD.md` existe y dice explícitamente "no validado para producción"
- `AUDITORIA_REPO.md` de 4000+ líneas documenta decisiones y trade-offs
- `ANALISIS_FALSOS_POSITIVOS_CONTROL.md` muestra que se analizaron los false positives en el control benigno
- El data exfiltration **FAIL** en `VALIDACION_POC.md` está documentado sin esconderlo

Eso es honestidad técnica.

---

## Problemas reales

### 1. El problema del bootstrap (el más serio)

El generador de ataques tiene parámetros fijos:
- IP atacante: siempre `10.0.0.99`
- Port scan: siempre 28–80 puertos en el mismo rango
- DNS exfil: mismo patrón `[18char].[18char].[14char].sync.ops.a1.evil-c2.com`
- Brute force: contraseñas aleatorias de exactamente 10 caracteres de `ascii_letters + digits`
- SQL injection: 4 payloads fijos

El modelo se entrenó con 60 instancias de ataque generadas por este script. La validación usa el **mismo script con los mismos parámetros**. El clasificador aprende a detectar "los ataques que genera `common.py`", no "port scans en general".

**Esto no es trampa, pero es una limitación crítica que el repo no nombra con suficiente claridad.**

Un port scan desde `192.168.1.200` a puertos 443, 80, 8080, 22, 3389 con timing lento no pasaría el mismo clasificador. Probablemente lo detectaría el HalfSpaceTrees o Suricata, pero el 99.76% de accuracy del clasificador es una métrica del generador, no del problema.

### 2. El 99.76% es una bandera roja

Los sistemas NDR reales contra tráfico real consiguen 85–95% en el mejor caso. El 99.76% de accuracy en clasificación con 819 eventos de test, todos sintéticos, en el mismo dominio de distribución que los de entrenamiento, no dice nada sobre el mundo real. No es mentira, pero presentarlo como resultado principal sin caveats es engañoso.

La distribución de clases tampoco ayuda: data exfiltration tiene solo 12 instancias de entrenamiento y 4 de test. Con esos números la métrica es inestable estadísticamente.

### 3. Los expert signals son heurísticas over-fit

Los umbrales de boost están calibrados al generador:
- Scan: `8+ puertos únicos + 4+ fallos en 60s`
- DNS: `entropy > 4.1 + NXDOMAIN`
- HTTP: `query > 80 chars`

El generador de DNS exfil produce labels de 18 caracteres de `ascii_letters + digits + '+/'`. La entropía de eso es predeciblemente alta. Los 80 chars de query son el resultado de los payloads SQL injection del generador. Estos umbrales no vienen de literatura NDR ni de análisis de tráfico real.

### 4. Data exfiltration es el canario en la mina

1 sola instancia de test, falla el clasificador ML, la detecta el expert signal pero solo marginalmente. Si hubiera más instancias o ligeramente diferentes, el resultado FAIL se vería peor. Este caso expone exactamente el bootstrap problem: el generador produce 1 flow enorme (650KB–3MB), el modelo no generaliza bien a ese patrón con tan pocos ejemplos de entrenamiento (12 en total).

### 5. Sin línea base de comparación

No hay ningún experimento que responda: "¿cuánto valor añade el ML sobre Suricata solo?". Si Suricata detectara el 80% de los ataques sin ML, la capa ML aporta diferencial marginal. Esa comparación no existe en el repo.

---

## Lo que NO es trampa

- El test set del clasificador (819 eventos) es **diferente** al training set (2460 eventos)
- El holdout del baseline (1795 eventos) es **diferente** al fit set (7184 eventos)
- Los ataques de validación se generan **en tiempo de ejecución**, no se resan del training
- El MODEL_CARD declara las limitaciones
- El FAIL de data exfil está documentado sin borrarlo

---

## Diagnóstico final

| Criterio | Puntuación | Nota |
|---|---|---|
| Arquitectura | 8/10 | Multi-capa con separación limpia |
| Feature engineering | 7/10 | Ratios vs. absolutos, bien razonado |
| Honestidad científica | 6/10 | Documenta limitaciones pero no el bootstrap problem |
| Validación | 4/10 | Circular: genera con A, evalúa con A |
| Generalización | 3/10 | No probada en datos reales ni con variaciones |
| Métricas | 5/10 | 99.76% no es creíble fuera del dominio sintético |

**En LinkedIn se puede enseñar como**: arquitectura NDR local con Suricata + ML para detección de anomalías y clasificación de ataques sobre tráfico sintético.  
**No se puede vender como**: sistema que detecta ataques reales con 99% de accuracy.

---

## Mejora propuesta: el Blind Generalization Test

### Por qué esta mejora y no otra

El mayor gap de credibilidad es la circularidad train/test. La mejora más pequeña con mayor impacto de calidad **y** de LinkedIn es demostrar que el modelo detecta ataques que no vio exactamente durante el entrenamiento.

No hace falta un dataset real (que requeriría días de integración). Basta con crear una segunda familia de generadores con parámetros distintos y medir qué ocurre.

### Qué se añade exactamente

**Un nuevo script: `simulation/generate_blind_test.py`**

Genera los mismos 5 tipos de ataque pero con variaciones que el modelo nunca vio:

| Ataque | Entrenamiento | Blind test |
|---|---|---|
| Port scan | IP `10.0.0.99`, puertos 28–80 | IP `172.16.0.50`, puertos 135–445 (Windows) |
| DNS exfil | Labels 18 chars, dominio `evil-c2.com` | Labels 12 chars, dominio `cdn-update.net` |
| Brute force | POST `/login`, 10-char pw | POST `/api/auth/token`, 8-char pw |
| SQL injection | 4 payloads UNION/OR | 4 payloads WAITFOR/EXEC/CAST |
| Data exfil | POST `/sync`, 650KB–3MB | POST `/api/v2/upload`, 100KB–400KB |

**Un nuevo script: `scripts/validate-blind.ps1`**

Corre el pipeline completo (Zeek + Suricata + features + score) sobre el blind test PCAP y genera una segunda tabla de resultados en `BLIND_TEST_RESULTS.md`.

**Un nuevo fichero: `BLIND_TEST_RESULTS.md`**

La pregunta honesta que responde: "¿Qué detecta el sistema cuando los ataques son ligeramente distintos a los del entrenamiento?".

### Por qué aumenta el impacto en LinkedIn

Un post con "entrenamos en X, probamos en Y diferente" tiene mucho más peso técnico que "entrenamos y evaluamos en el mismo dominio". Hay tres posibles narrativas dependiendo del resultado:

**Escenario A — el modelo generaliza bien (detecta ≥4/5 familias)**  
> "Entrenamos un clasificador con ataques sintéticos del tipo A. Sin reentrenar, lo expusimos a ataques del tipo B con IPs, dominios y payloads distintos. Detectó 4 de 5 familias. Esto valida que aprende el comportamiento, no el patrón exacto."

**Escenario B — el modelo generaliza parcialmente (detecta 2-3/5)**  
> "Cuando cambiamos la IP, el dominio C2 y el endpoint objetivo, el clasificador supervisado falla pero el detector de anomalías y Suricata siguen funcionando. Esto valida la decisión de diseño multi-capa: si una capa falla, las otras cubren."

**Escenario C — el modelo falla (detecta ≤1/5)**  
> "El clasificador aprende a distinguir los ataques de su generador, no los ataques en general. Para producción habría que ampliar el corpus. Este resultado honesto es valioso: la arquitectura es sólida, el dataset sintético no."

Los tres escenarios son publicables. El B y el C son más honestos y más interesantes que el A. En LinkedIn, la honestidad técnica bien articulada supera al "funciona perfecto".

### Esfuerzo estimado

- `generate_blind_test.py`: ~100 líneas, copiar patrones de `common.py` con parámetros distintos
- `validate-blind.ps1`: ~60 líneas, igual que `validate-poc.ps1`
- `BLIND_TEST_RESULTS.md`: se genera automáticamente

**Tiempo estimado: 3–4 horas.**

### Lo que NO propongo y por qué

- **Dashboard**: el usuario lo descarta. Con el modelo actual no aporta.
- **Eval contra CICIDS2017**: sería lo más riguroso pero requiere integración de días, preprocesado de CSV real, alinear features. Fuera del scope de una mejora pequeña.
- **Confusion matrix con matplotlib**: mejora cosmética, no cambia la sustancia.
- **Cross-validation**: requeriría regenerar todo el pipeline de entrenamiento, no es "pequeña".

La mejora del blind test es pequeña en código, grande en argumento, y honesta sobre lo que el sistema puede y no puede hacer.
