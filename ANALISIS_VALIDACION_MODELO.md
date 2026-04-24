# Analisis de validacion del modelo y simulaciones

## Que significan las columnas

`ml_detections` es el numero de flujos Zeek donde el ML final ha detectado algo y ha escrito una etiqueta en `ml_label`.

Puede venir de dos sitios:

- clasificador supervisado aprendido: etiqueta familias conocidas (`port_scan`, `dns_exfiltration`, `brute_force_http`, `sql_injection`, `data_exfiltration`);
- detector no supervisado: etiqueta `novel_anomaly` cuando el `raw_score` supera el threshold.

`ml_anomalies` queda reservado para la deriva cruda no supervisada: numero de flujos donde `raw_score` supera el threshold guardado en `model/meta.json`.

En codigo:

```python
is_ml_anomaly = score >= threshold
```

No depende de Suricata ni de reglas expertas.

`expert_signals` es el numero de flujos donde las heuristicas explicables de `pipeline/anomaly_utils.py` han sumado `behavioral_boost > 0`. Ejemplos:

- `scan_ports_60s`
- `dns_query_shape`
- `http_payload_shape`
- `volume_spike`

Estas senales no son "la IA". Son una capa explicable para priorizar y para que el dashboard ensene por que algo parece sospechoso.

`layers` resume que capas han visto algo:

- `ML`: al menos un flujo tiene `is_ml_detection=true`.
- `DerivaML`: al menos un flujo supera el threshold del detector no supervisado.
- `Expert`: al menos un flujo tiene `behavioral_boost > 0`.
- `Suricata`: hay al menos una alerta Suricata esperada para ese escenario.

## Lectura del resultado recibido

Resultado recibido:

```text
[FAIL] Control benigno: ml_raw=0,939227, ml_anomalies=3, expert_signals=0, layers=ML
[PASS] Port Scan: ml_raw=0,939227, ml_anomalies=3, expert_signals=42, layers=ML, Expert, Suricata
[PASS] DNS Exfiltration: ml_raw=0,939227, ml_anomalies=3, expert_signals=24, layers=ML, Expert
[PASS] Brute Force HTTP: ml_raw=0,939227, ml_anomalies=3, expert_signals=0, layers=ML, Suricata
[PASS] SQL Injection: ml_raw=0,939227, ml_anomalies=3, expert_signals=2, layers=ML, Expert, Suricata
[PASS] Data Exfiltration: ml_raw=0,966409, ml_anomalies=4, expert_signals=1, layers=ML, Expert
```

Lo sospechoso es que casi todos los escenarios tienen exactamente `ml_raw=0,939227` y `ml_anomalies=3`. Eso no demuestra que cada ataque haya sido detectado por ML. Demuestra que el baseline benigno ya traia 3 anomalias ML, y el validador las estaba arrastrando dentro de cada escenario de ataque.

Por eso `Brute Force HTTP` pasaba con `-RequireMl` aunque `expert_signals=0`: el ML probablemente no estaba detectando el brute force; estaba heredando las 3 anomalias del control.

## Cambios aplicados

### 0. ML principal: detectar y etiquetar

Decision aplicada: el dashboard y el validador tratan como deteccion ML principal a `is_ml_detection` + `ml_label`.

Esto evita vender como IA una regla experta y evita depender de `raw_score` para ataques conocidos. El detector no supervisado sigue existiendo, pero se presenta como deriva/rareza sin etiqueta.

Campos nuevos en `pipeline/score.py`:

- `is_ml_detection`
- `ml_label`
- `ml_detection_source`

### 0.1 Calibracion aprendida del clasificador

En una validacion anterior el unico fallo restante era `Data Exfiltration`:

```text
[FAIL] Data Exfiltration: ml_raw=0,78903, ml_anomalies=0, classifier=0, pred=-, expert_signals=1, layers=Expert
```

El artefacto `output/live_scores.jsonl` mostraba que el clasificador si estaba prediciendo la clase correcta:

```text
attack_prediction = data_exfiltration
attack_confidence = 0.254
detection_threshold = 0.45
```

Por eso el validador no lo contaba como deteccion. El modelo ve la exfiltracion como la clase mas probable, pero la PoC genera ese ataque como un solo flujo enorme; con un clasificador por centroides la confianza softmax queda repartida entre varias clases aunque el ranking sea correcto.

Cambio aplicado:

- `pipeline/score.py`: soporta `class_thresholds` por clase.
- `pipeline/train_attack_classifier.py`: aprende esos umbrales desde el holdout, usando las confianzas correctas por clase.
- `simulation/generate_attack_train.py`: genera variantes de cada ataque para que el clasificador aprenda rangos, no una unica muestra fija.
- La salida de scoring incluye `attack_detection_threshold` para auditar que umbral se uso por fila.

Esto no baja el umbral global del clasificador a mano. El umbral por clase sale de datos etiquetados de entrenamiento.

### 1. Validacion por escenario real

Archivo: `scripts/validate-poc.ps1`

Antes, para cada ataque el script restauraba el baseline benigno, procesaba el ataque y luego calculaba metricas sobre todo `output/live_scores.jsonl`. Eso mezcla:

- flujos benignos del control;
- flujos del ataque actual.

Ahora `Run-Attack` guarda cuantos flujos y alertas habia justo despues de restaurar el baseline, y `Get-ValidationResult` evalua solo lo nuevo:

```powershell
$baselineRowCount = @(Read-JsonLines $liveScores).Count
$baselineAlertCount = @(Read-JsonLines $evePath | Where-Object { $_.event_type -eq "alert" }).Count
...
Get-ValidationResult ... -StartRow $baselineRowCount -StartAlert $baselineAlertCount
```

El reporte tambien incluye `Flujos evaluados` para que se vea si una fila esta midiendo el control o solo el ataque.

### 2. Entrenamiento con normalidad densa y quieta

Archivo: `scripts/poc-train.ps1`

El entrenamiento principal sigue usando:

```powershell
8000 conexiones / 30 minutos
```

Pero ahora suma un perfil benigno quieto:

```powershell
1200 conexiones / 100 minutos
```

Motivo: el control de validacion usa `12 conexiones / 1 minuto`. Si el modelo solo ve una red densa, HalfSpaceTrees puede marcar como raro el bajo trafico. En una red real, poco trafico no deberia ser anomalo por si solo.

Esto no entrena con ataques. Sigue siendo aprendizaje de normalidad, pero con dos regimenes normales:

- red activa;
- red quieta.

### 3. Demo consistente

Archivo: `scripts/demo-jefe.ps1`

Si falta el modelo, ahora entrena con `ThresholdQuantile 0.999`, igual que `poc-train.ps1`. Antes usaba `0.95`, demasiado sensible para demo.

## Tiene sentido usar Random Forest?

No como modelo principal de esta PoC.

Random Forest es supervisado: necesita ejemplos etiquetados de normal, port scan, DNS exfil, brute force, SQLi, etc. Eso sirve para clasificar ataques ya simulados, pero conceptualmente cambia la historia:

- antes: "aprende la red normal y detecta desviaciones";
- despues: "aprende mis ataques sinteticos y reconoce cosas parecidas".

Para ensenarlo a un jefe como NDR con IA, el enfoque correcto aqui es:

- mantener un detector no supervisado u online para baseline (`HalfSpaceTrees`, `IsolationForest`, One-Class SVM, etc.);
- mostrar reglas expertas y Suricata como capas separadas;
- no vender las reglas expertas como IA.

HalfSpaceTrees tiene sentido porque River permite scoring online y aprendizaje incremental. IsolationForest podria ser una alternativa batch mas estable, pero no es "tiempo real" incremental de la misma forma. Random Forest solo lo meteria como segunda capa opcional si decides convertir la PoC en un clasificador supervisado de ataques conocidos.

## Como validar despues de estos cambios

Reentrena, porque cambia el dataset normal usado para el modelo:

```powershell
.\scripts\poc-train.ps1
.\scripts\validate-poc.ps1 -RequireMl -KeepArtifacts
```

Luego mira:

- `VALIDACION_POC.md`: `Control benigno` deberia tener `ml_anomalies = 0`.
- En ataques, `ml_anomalies` ya no incluye las anomalias del control.
- Si algun ataque falla con `-RequireMl` pero aparece en `Expert` o `Suricata`, eso significa que lo detecta la PoC multicapa, no el ML puro. Es una informacion util, no un fallo que haya que esconder.
