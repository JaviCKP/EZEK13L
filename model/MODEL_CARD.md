# Model card PoC NDR

## Proposito

Baseline local para detectar deriva/anomalias en trafico sintetico de laboratorio NDR. No es un detector validado para produccion ni sustituye reglas IDS.

## Modelo

- Libreria: River
- Baseline no supervisado: `MinMaxScaler + HalfSpaceTrees`
- Clasificador supervisado: `CentroidAttackClassifier` entrenado con trafico sintetico etiquetado
- Tipo: deteccion online de anomalias + clasificacion de familias conocidas
- Score alto: mas anomalo en baseline; probabilidad alta en clasificador
- Persistencia local: `model/model.pkl`
- Metadata: `model/meta.json`
- Clasificador: `model/attack_classifier.pkl`
- Metadata clasificador: `model/attack_classifier_meta.json`

## Capas de scoring

El dashboard y `pipeline/score.py` muestran estos valores:

- `raw_score`: salida directa del modelo.
- `attack_prediction`: familia predicha por el clasificador supervisado.
- `attack_confidence`: confianza/probabilidad del clasificador.
- `attack_detection_threshold`: umbral aplicado a esa prediccion.
- `is_ml_detection`: deteccion ML final, por clasificador aprendido o por deriva.
- `ml_label`: etiqueta visible del ML (`normal`, familia de ataque o `novel_anomaly`).
- `behavioral_boost`: senales expertas explicables de comportamiento.
- `hybrid_score`: suma visible para priorizacion.

La deteccion ML principal se decide con el clasificador supervisado aprendido y queda en `is_ml_detection` + `ml_label`. La salida no supervisada `raw_score` queda como deriva/rareza sin etiqueta. Los boosts no cuentan como acierto de ML; son senales expertas auditables para patrones muy claros:

- presion de scan;
- DNS con entropia/forma sospechosa;
- payload HTTP con forma de abuso;
- picos de volumen.

Para que el modelo pueda aprender bursts sin codificar nombres de ataque, las features incluyen conteos temporales genericos HTTP por origen/par, errores 4xx/5xx, POSTs y ratios en ventanas de 60s y 300s.

El clasificador usa un umbral global y puede aplicar umbrales por clase aprendidos en el holdout de entrenamiento. No se fija a mano una clase concreta: `train_attack_classifier.py` calibra esos umbrales con las confianzas observadas en ejemplos etiquetados que no han entrado en el ajuste inicial.

## Datos

Entrenamiento con trafico sintetico generado por `simulation/generate_normal.py` y `simulation/generate_attack_train.py`. El flujo de entrenamiento combina un perfil normal activo, un perfil normal quieto y ataques sinteticos etiquetados para el clasificador. La validacion usa un control benigno y cinco ataques sinteticos: port scan, DNS exfiltration, brute force HTTP, SQL injection y data exfiltration.

## Limitaciones

- Dataset pequeno y sintetico.
- No mide precision/recall real.
- HalfSpaceTrees puede perder fuerza si muchas anomalias aparecen agrupadas en la misma ventana.
- El clasificador supervisado reconoce familias vistas en simulacion; no prueba deteccion universal de ataques reales.
- El pickle debe cargarse solo desde una fuente confiable.
- Las reglas Suricata descargadas son artefactos locales, no codigo propio.

## Reproduccion

```powershell
.\scripts\poc-train.ps1
.\scripts\validate-poc.ps1
.\scripts\demo-jefe.ps1
```
