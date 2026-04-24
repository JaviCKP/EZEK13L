# Analisis de falsos positivos en Control benigno

## Resumen corto

El problema no era que Suricata fallara ni que hubiera que guiar mas al modelo. El fallo venia de la calibracion del modelo: `pipeline/train_baseline.py` usaba el ultimo 20% cronologico del dataset como holdout para calcular el threshold. Como las features principales son ventanas temporales de 60s y 300s, el final del PCAP de entrenamiento representa una red ya estabilizada y densa. El control benigno de `validate-poc.ps1` es pequeno y cae en otra zona normal, pero poco representada en esa calibracion.

La solucion correcta es calibrar el threshold con una muestra normal repartida por todo el entrenamiento, no subir artificialmente el trafico benigno de validacion.

## Que estaba pasando

`scripts/poc-train.ps1` genera trafico normal sintetico y lo convierte en features con Zeek. El modelo River `HalfSpaceTrees` aprende esas features, y el threshold se calcula con una parte del propio trafico normal.

Antes:

```python
train_rows = rows[:-holdout_count]
calibration_rows = rows[-holdout_count:]
```

Eso tiene un sesgo fuerte en este repo porque `build_features.py` calcula features acumuladas por ventana, por ejemplo:

- `src_conn_count_60s`
- `src_conn_count_300s`
- `pair_conn_count_60s`
- `src_total_bytes_60s`
- ratios HTTP por ventana

Al inicio de un PCAP normal, esas ventanas aun estan arrancando. Al final, ya tienen mucha mas historia acumulada. Si el threshold solo mira el final, aprende que lo normal es trafico denso. Luego `validate-poc.ps1`, que por defecto crea un control benigno pequeno (`12` conexiones en `1` minuto), puede producir varios puntos benignos con score alto.

## Por que no arreglarlo con 300 conexiones / 5 minutos

Ese cambio fue una mala direccion y queda revertido. Aumentar el control a `300` conexiones durante `5` minutos hizo tres cosas malas:

- Subio los falsos positivos ML absolutos porque genero muchos mas flujos.
- Activo senales expert como `volume_spike` por trafico benigno grande.
- Puede disparar reglas locales de Suricata, por ejemplo la regla de posible SYN scan si una workstation normal supera el contador configurado.

En una PoC para ensenar, el control debe seguir siendo rapido y legible. Si hay que cambiar algo, se cambia la calibracion del modelo, no se fuerza la validacion para que parezca el entrenamiento.

## Cambios aplicados

### 1. Calibracion del modelo

Archivo: `pipeline/train_baseline.py`

He cambiado el holdout cronologico por un holdout aleatorio determinista:

```python
holdout_indices = set(rng.choice(len(rows), size=holdout_count, replace=False).tolist())
train_rows = [row for index, row in enumerate(rows) if index not in holdout_indices]
calibration_rows = [row for index, row in enumerate(rows) if index in holdout_indices]
```

Esto mantiene el entrenamiento sobre trafico normal, pero el threshold se calcula con muestras de todo el PCAP: arranque, regimen medio y regimen denso.

Tambien se guardan en `model/meta.json` estos campos nuevos cuando se reentrena:

- `holdout_ratio`
- `calibration_strategy`
- `calibration_seed`

### 2. `validate-poc.ps1` vuelve a ser rapido

Archivo: `scripts/validate-poc.ps1`

Se mantienen los defaults correctos para la validacion PoC:

```powershell
[int]$NormalConnections = 12
[double]$NormalDurationMinutes = 1
```

El control benigno no debe inflarse para esconder un problema de calibracion.

### 3. Entrenamiento atomico

Archivo: `scripts/poc-train.ps1`

Antes el script borraba `model/model.pkl` y `model/meta.json` al principio. Si Docker fallaba, el repo se quedaba sin modelo. Ahora entrena en artefactos temporales (`*.next.*`) y solo sustituye el modelo final cuando han terminado bien generacion, Zeek, features y entrenamiento.

### 4. Fix de quoting Docker / PowerShell

Archivos:

- `scripts/poc-train.ps1`
- `scripts/validate-poc.ps1`
- `scripts/poc-watcher.ps1`
- `scripts/demo-jefe.ps1`
- `scripts/run-dashboard.ps1`
- `scripts/update-suricata-rules.ps1`

Los helpers `Invoke-Process` ahora pasan a `Start-Process` una linea de argumentos ya quoteada. Esto evita errores como:

```text
mkdir: missing operand
```

Ese error salia porque PowerShell partia mal el argumento compuesto de `sh -c "mkdir ... && suricata ..."`.

### 5. Fix de `poc-watcher.ps1`

Archivo: `scripts/poc-watcher.ps1`

`Invoke-Service` ahora evita duplicar el entrypoint cuando se usa `docker compose run --entrypoint sh`. Asi el mismo comando sirve en modo live y en validacion con contenedores persistentes.

## Como validar ahora

Hay que reentrenar, porque el cambio importante afecta a `model/model.pkl` y `model/meta.json`:

```powershell
.\scripts\poc-train.ps1
.\scripts\validate-poc.ps1 -RequireMl
```

Resultado esperado:

- `Control benigno`: `PASS`, con `ml_anomalies = 0` o al menos `ml_raw` por debajo del threshold.
- Ataques: `PASS` por ML si se usa `-RequireMl`; tambien pueden aparecer capas `Expert` y `Suricata`, pero no son las que deciden el modo estricto.

Si vuelve a fallar el control, el siguiente paso correcto no es meter reglas manuales al ML. Es comparar las distribuciones de features entre `output/train_poc_features.jsonl` y el control de `output/live_scores.jsonl`, y ajustar el generador normal o las features de ventana.
