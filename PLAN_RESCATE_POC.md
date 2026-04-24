# Plan de rescate de la PoC NDR

## Diagnostico franco

La arquitectura anterior no era suficiente para vender "IA que detecta ataques":

- Suricata si aporta valor: firmas, trazabilidad y evidencia entendible.
- `HalfSpaceTrees` solo aporta novelty detection. Es util para rarezas, pero inestable si el baseline normal no cubre todos los regimenes de trafico.
- `expert_signals` son reglas deterministas. Sirven como explicacion, pero no deben venderse como IA.

La salida es separar la historia en tres capas honestas:

1. **Suricata**: evidencia por firmas.
2. **Clasificador IA supervisado**: reconoce familias de ataque entrenadas en trafico sintetico etiquetado.
3. **Detector de rarezas**: detecta desviaciones no vistas respecto al baseline normal.

Eso permite ensenar probabilidades, clase predicha, matriz de validacion y dashboard en vivo sin hacer pasar heuristicas por ML.

## Cambios implementados

### Clasificador supervisado

Nuevo archivo:

- `pipeline/train_attack_classifier.py`

Usa `CentroidAttackClassifier`, un clasificador supervisado local basado en centroides estandarizados por clase. Para esta PoC sintetica es mas estable y rapido que el ARF online anterior. Entrena con JSONL de features etiquetadas:

- `normal`
- `port_scan`
- `dns_exfiltration`
- `brute_force_http`
- `sql_injection`
- `data_exfiltration`

Genera:

- `model/attack_classifier.pkl`
- `model/attack_classifier_meta.json`

La metadata incluye clases, conteos, threshold de deteccion y metricas de test.

### Generador de entrenamiento de ataques

Nuevo archivo:

- `simulation/generate_attack_train.py`

Genera PCAPs con varias repeticiones de una familia de ataque para entrenar el clasificador sin depender del flujo interactivo.

### Entrenamiento unificado

Archivo modificado:

- `scripts/poc-train.ps1`

Ahora entrena:

- baseline no supervisado normal activo + normal quieto;
- clasificador supervisado normal + cinco familias de ataque.

Parametros nuevos:

```powershell
-QuietConnections 1200
-QuietDurationMinutes 100
-AttackRepeats 12
-SkipClassifier
```

### Scoring enriquecido

Archivo modificado:

- `pipeline/score.py`

Si existe `model/attack_classifier.pkl`, cada flujo obtiene:

- `attack_prediction`
- `attack_confidence`
- `attack_probabilities`
- `is_attack_classifier_detection`

La anomalia pura sigue siendo `is_ml_anomaly`. El clasificador es otra capa ML, separada.

### Validacion corregida

Archivo modificado:

- `scripts/validate-poc.ps1`

Ahora cada ataque se evalua solo sobre sus flujos nuevos, no mezclado con el baseline benigno. El reporte incluye:

- flujos evaluados;
- anomalias ML;
- detecciones del clasificador;
- prediccion IA;
- senales expert;
- Suricata.

Con `-RequireMl`, ahora pasa si lo detecta el novelty detector o el clasificador supervisado.

### Dashboard

Archivos modificados:

- `dashboard/api.py`
- `dashboard/script.js`
- `dashboard/index.html`
- `dashboard/style.css`

El dashboard muestra:

- metrica `ATAQUES IA`;
- estado `Ataque IA`;
- clase predicha;
- confianza;
- anomalia raw separada.

## Como venderlo

Frase corta:

> "La PoC combina Suricata para evidencia por firma, un clasificador IA entrenado con trafico sintetico para reconocer familias de ataque y un detector online de desviaciones para comportamiento no visto."

Lo que no hay que decir:

> "La IA aprende sola cualquier ataque."

Eso no es defendible con un dataset sintetico pequeno.

## Como validar

```powershell
.\scripts\poc-train.ps1
.\scripts\validate-poc.ps1 -RequireMl -KeepArtifacts
.\scripts\demo-jefe.ps1
```

Si hace falta iterar rapido:

```powershell
.\scripts\poc-train.ps1 -Connections 2500 -DurationMinutes 15 -QuietConnections 600 -QuietDurationMinutes 60 -AttackRepeats 6
.\scripts\validate-poc.ps1 -RequireMl -KeepArtifacts
```

El reporte bueno debe ensenar:

- control benigno sin deteccion de clasificador;
- ataques con `Prediccion IA` correcta o Suricata/Expert como respaldo;
- `Flujos evaluados` distinto por escenario, demostrando que ya no se arrastra el baseline.
