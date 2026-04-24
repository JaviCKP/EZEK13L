# Auditoria repo lab-ndr

Fecha: 2026-04-24

## Actualizacion aplicada

Cambios aplicados tras esta auditoria:

- `requirements.txt` queda fijado a versiones concretas.
- Las reglas descargadas de Suricata quedan marcadas como artefacto generado en `.gitignore`; se mantiene `suricata/etc/local.rules` como codigo propio.
- Se elimino `Invoke-Expression` de los scripts principales.
- `scripts/poc-live.ps1` preserva `.gitkeep` al limpiar colas live.
- `simulation/generate_live.py` puede inyectar ataques automaticos durante el flujo live.
- Se anadio `scripts/demo-jefe.ps1` para arrancar una demo con dashboard, trafico normal y ataques periodicos.
- El dashboard muestra `raw_score`, `behavioral_boost`, score final y factores de comportamiento.
- Se quito CORS abierto del dashboard local.
- Se sustituyo renderizado de tablas basado en `innerHTML` por nodos con `textContent`.
- `pipeline/train_baseline.py` guarda version River, hash de schema y distribucion de calibracion en nuevas metadata.
- `pipeline/score.py` corrige `learn_below` cuando una metadata antigua lo deja en cero.
- Se anadio `model/MODEL_CARD.md`.

## Resumen ejecutivo

El repo esta bien orientado como PoC local de NDR: genera trafico sintetico, extrae features con Zeek, correlaciona con Suricata, puntua con un modelo online de River y lo muestra en un dashboard. La idea es valida para una demo tecnica.

El punto mas importante: no lo venderia como "IA que detecta ataques" en bruto. Lo venderia como "NDR lab hibrido: anomaly detection online + reglas Suricata + explicabilidad por factores de comportamiento". Esa frase es mas honesta y mas fuerte.

Lo que mas resta calidad ahora mismo:

- Hay artefactos pesados/generados en el arbol: `suricata/lib/rules/suricata.rules` pesa unos 43 MB y `model/model.pkl` unos 4.2 MB.
- La reproducibilidad es fragil: `requirements.txt` no tiene versiones fijadas y el modelo pickle depende de la version de River.
- El modelo carga y es valido como PoC, pero esta entrenado con solo 247 eventos sinteticos. No es evidencia de validez real.
- El scoring final depende mucho de boosts manuales (`pipeline/anomaly_utils.py`), no solo del modelo.
- Los scripts PowerShell usan `Invoke-Expression`, que es una chapuza comun pero evitable.
- El dashboard tiene buen impacto visual, pero usa CDNs y `innerHTML` con datos procedentes de logs.

## Verificaciones realizadas

- Mapeo completo con `rg --files`.
- Lectura de `README.md`, `requirements.txt`, `.gitignore`, `Dockerfile`, `docker-compose.yml`, scripts, pipeline, simulacion, dashboard y configuracion Suricata.
- Compilacion Python: `python -m compileall -q dashboard pipeline simulation` paso sin errores.
- Sintaxis JS: `node --check dashboard/script.js` paso sin errores.
- Dependencias locales importan correctamente: River, pandas, numpy, scapy, FastAPI y uvicorn.
- Modelo local cargado correctamente desde `model/model.pkl`.
- Tipo real del modelo: `river.compose.pipeline.Pipeline`.
- Version local observada: River `0.24.2`.
- Docker no se pudo validar desde esta sesion: fallo por permisos al conectar con `npipe:////./pipe/docker_engine`. Por tanto no ejecute la matriz completa de `scripts/validate-poc.ps1`.
- No hay `.git` visible en el sandbox, asi que no puedo asegurar que ficheros estan trackeados. Marco como "borrar del repo/ignorar" los que por naturaleza son artefactos.

## Mapa rapido del repo

- `simulation/`: generadores de PCAP normal/live/ataques.
- `pipeline/build_features.py`: transforma logs JSON de Zeek en features por conexion.
- `pipeline/train_baseline.py`: entrena baseline River HST y genera `model/model.pkl` + `model/meta.json`.
- `pipeline/score.py`: puntua eventos, aplica boost comportamental y controla aprendizaje online.
- `pipeline/anomaly_utils.py`: heuristicas de scan, HTTP sospechoso, DNS sospechoso y volumen.
- `pipeline/suricata_utils.py`: clasifica alertas Suricata como amenaza, telemetria o ruido.
- `scripts/`: orquestacion Docker, live, training, watcher, validacion y limpieza.
- `dashboard/`: FastAPI + HTML/CSS/JS.
- `suricata/etc/`: config y reglas locales.
- `suricata/lib/rules/`: reglas comunitarias descargadas/generadas.

## Basura o artefactos a borrar/ignorar

### 1. `suricata/lib/rules/suricata.rules`

Tamano: ~43 MB.

Motivo: parece descargado por `suricata-update`, no fuente propia. `suricata/etc/suricata.yaml:2319` lo referencia como `/var/lib/suricata/rules/suricata.rules`, pero el repo ya tiene `scripts/update-suricata-rules.ps1` para generarlo.

Recomendacion:

- No versionarlo.
- Anadir a `.gitignore` algo como:

```gitignore
suricata/lib/rules/*
!suricata/lib/rules/.gitkeep
```

- Mantener `suricata/etc/local.rules` como codigo propio.
- Opcional: hacer que el flujo local funcione solo con `local.rules` si las community rules no estan descargadas, o documentar "run update-suricata-rules first".

### 2. `suricata/lib/rules/classification.config`

Motivo: duplicado/generado. La configuracion activa apunta a `suricata/etc/classification.config` via `suricata/etc/suricata.yaml:2325`.

Recomendacion: no versionarlo. Si Suricata lo necesita tras `suricata-update`, que se regenere.

### 3. `model/model.pkl` y `model/meta.json`

Estado actual:

- `.gitignore:26` ignora `model/*.pkl`.
- `.gitignore:27` ignora `model/meta*.json`.
- `README.md:60` dice que no se borran porque son necesarios para operar.

Esto esta bien para un workspace local, pero es una tension para un repo publico: un clon limpio no tendra modelo, aunque el README diga que es necesario.

Recomendacion:

- No versionar `model/model.pkl`.
- Mantener `model/meta.json` solo si quieres publicar un ejemplo de auditoria del modelo; si no, regenerarlo con `scripts/poc-train.ps1`.
- Anadir un `model/MODEL_CARD.md` con parametros, fecha, dataset sintetico, limitaciones y comando de reproduccion.

### 4. Directorios `data/`, `logs/`, `output/`

Ahora mismo estan limpios y solo tienen `.gitkeep`, correcto.

Riesgo: `scripts/poc-live.ps1:21-24` borra directorios enteros (`data/live_in`, `data/live_done`, `data/live_error`, `logs/live`) y luego los recrea en `scripts/poc-live.ps1:30-33`. Eso elimina los `.gitkeep`.

Recomendacion: cambiar ese script para limpiar contenido preservando `.gitkeep`, igual que hace `scripts/clean-repo.ps1`.

### 5. `__pycache__`

El `.gitignore` ya lo cubre y `scripts/clean-repo.ps1:57-59` lo limpia. Correcto.

## Codigo muerto o legacy

No veo funciones Python claramente muertas en el nucleo. Un escaneo AST simple solo marco las rutas FastAPI `serve_index` y `get_dashboard_data`, pero son entrypoints por decorador y no son codigo muerto.

Lo que si huele a legacy:

- `dashboard/api.py:252-253` mantiene fallbacks a `output/detections.jsonl` y `logs/offline/test_suricata/eve.json`. Si esos nombres son de una version anterior, quitarlos simplifica el dashboard.
- `scripts/clean-repo.ps1:27-54` limpia ficheros antiguos (`benign_150k.pcap`, `model_eval.pkl`, `meta_smoke.json`, etc.) que no existen en el arbol actual. No rompe nada, pero revela deuda historica. Puedes dejarlo si te protege de restos locales, o moverlo a una seccion `legacy cleanup`.
- `simulation/common.py:58` declara `NORMAL_BUILDERS` como lista vacia y `simulation/common.py:585` lo reasigna. Es menor, pero puede quedarse solo como anotacion o eliminarse si no hace falta.

## Codigo mal hecho / chapuzas

### Alta prioridad

1. `Invoke-Expression` en PowerShell.

Referencias:

- `scripts/poc-train.ps1:16`
- `scripts/poc-watcher.ps1:29`
- `scripts/validate-poc.ps1:38`

Problema: compone strings y los ejecuta. Es fragil con quoting, dificil de auditar y abre la puerta a ejecucion accidental si un parametro llega mal escapado.

Arreglo recomendado: usar arrays de argumentos y ejecutar `& docker @args`, o funciones especificas por paso.

2. Dependencias sin pinning.

Referencias:

- `requirements.txt:1-6`
- `docker-compose.yml:31` usa `zeek/zeek:lts`
- `docker-compose.yml:37` usa `jasonish/suricata:latest`

Problema: el modelo pickle depende de River y el pipeline depende de Zeek/Suricata. Con versiones flotantes, una demo puede romperse de un dia a otro.

Arreglo recomendado:

```txt
river==0.24.2
pandas==2.3.3
numpy==2.4.4
scapy==2.7.0
fastapi==0.109.0
uvicorn==0.27.0
```

Y fijar imagenes Docker por tag concreto o digest.

3. Dashboard con `innerHTML` usando datos de logs.

Referencias:

- `dashboard/script.js:178`
- `dashboard/script.js:194`
- `dashboard/script.js:200`

Problema: `suricata_signature`, IPs o valores derivados de logs entran en HTML. En local parece poco grave, pero una demo de seguridad no deberia tener XSS facil.

Arreglo recomendado: crear nodos y usar `textContent`.

4. CORS abierto.

Referencia: `dashboard/api.py:33-36`.

Problema: para local vale, pero queda poco serio en un proyecto de seguridad.

Arreglo recomendado: restringir a `http://localhost:8501` o eliminar CORS si frontend y API salen del mismo origen.

### Media prioridad

5. Uso de pickle para el modelo.

Referencias:

- `pipeline/train_baseline.py:3`
- `pipeline/train_baseline.py:40`
- `pipeline/score.py:136`
- `pipeline/score.py:145`

Problema: pickle no es seguro para modelos no confiables y es fragil entre versiones. Para esta PoC local vale, pero documentalo.

Arreglo recomendado: guardar tambien `requirements.lock`, `river_version`, `feature_schema_hash` y `model_created_at` en `meta.json`.

6. `learn_below` actual bloquea casi todo aprendizaje positivo.

Referencias:

- `model/meta.json:3` tiene `"learn_below": 0.0`.
- `pipeline/score.py:156-159` bloquea aprendizaje si `score > learn_below`.

Efecto: cualquier evento con score positivo queda bloqueado salvo que score sea exactamente 0. Si quieres demostrar aprendizaje online real, esto puede dejar el contador `Aprendidos` casi plano.

Arreglo recomendado: revisar calibracion del `learn_quantile`, guardar distribucion de scores de holdout y mostrarla en el reporte de validacion.

7. `validate-poc.ps1` crece en memoria con `+=`.

Referencia: `scripts/validate-poc.ps1:99`.

No importa con pocos eventos, pero es una mala costumbre en PowerShell. Mejor usar una lista generica o emitir stream.

8. Frontend depende de internet.

Referencias:

- `dashboard/index.html:11` Google Fonts.
- `dashboard/index.html:14` Plotly CDN.

Para un video o demo en LinkedIn, si el navegador no tiene red, el dashboard pierde graficas o tipografia. Mejor empaquetar assets locales o tener fallback.

## Revision del modelo IA

### Veredicto

El modelo elegido es correcto para una PoC de deteccion de anomalias en streaming, con matices.

El pipeline real cargado es:

- `MinMaxScaler`
- `HalfSpaceTrees`
- `n_trees=50`
- `height=10`
- `window_size=512`
- `seed=42`

Esto coincide con `pipeline/train_baseline.py:23-29` y `model/meta.json:10-14`.

La documentacion oficial de River dice que Half-Space Trees es una variante online de isolation forests, que funciona bien cuando las anomalias estan dispersas, que asume features en rango `[0, 1]` si no se especifican limites y que `MinMaxScaler` es una opcion recomendada si no conoces limites a priori. Tambien indica que scores altos significan anomalia. Fuente: https://riverml.xyz/latest/api/anomaly/HalfSpaceTrees/

Por tanto, el uso de `MinMaxScaler() + HalfSpaceTrees()` es tecnicamente coherente.

### Donde es fuerte

- Es online/incremental, encaja con un watcher live.
- El score es barato y rapido.
- La pipeline separa bien `raw_score`, `behavioral_boost`, `behavioral_factors` e `is_anomaly`.
- El aprendizaje intenta evitar poisoning: bloquea aprendizaje si Suricata alerta o si el score supera umbral.
- La combinacion con Suricata hace la demo mas creible que usar solo ML.

### Donde es debil

- El entrenamiento observado en `model/meta.json:4-6` tiene solo 247 eventos, con 198 fit y 49 holdout. Eso no valida un NDR real.
- El dataset es sintetico. Sirve para demo, no para afirmar eficacia general.
- El threshold actual es `0.081184544` (`model/meta.json:2`), bastante bajo.
- El `learn_below` actual es `0.0` (`model/meta.json:3`), lo que puede impedir aprendizaje online util.
- El score final es hibrido: `pipeline/anomaly_utils.py:143-150` suma hasta `0.35` de boost manual.
- En una prueba con features sinteticas sparse, los escenarios de port scan, DNS exfil, SQL HTTP y data exfil superaron el umbral por boost comportamental aunque `raw_score` salio `0.0`. Esto no invalida la demo, pero obliga a presentarla como sistema hibrido.

### Riesgo conceptual importante

HalfSpaceTrees puede fallar cuando las anomalias estan agrupadas en ventanas. Justo varios ataques sinteticos generan bursts. Vuestra capa de reglas/boosts compensa ese punto, pero entonces el valor diferencial no es "la IA sola", sino la correlacion.

Mensaje honesto para LinkedIn:

> "He montado un laboratorio NDR local que fusiona Zeek, Suricata y anomaly detection online con explicabilidad por comportamiento: scan pressure, DNS shape, HTTP payload shape y volume spikes."

## Pareto 80/20 para mas impacto en LinkedIn

Estas son las acciones que, con poco cambio relativo, mas suben el wow y la credibilidad.

### 1. Crear un modo demo reproducible de 90 segundos

Objetivo: una sola orden que genere un replay controlado y deje el dashboard con datos vistosos.

Comando ideal:

```powershell
.\scripts\demo-linkedin.ps1
```

Debe hacer:

- limpiar estado;
- arrancar dashboard;
- generar control benigno;
- inyectar 5 ataques;
- ejecutar watcher en modo `-NoLearn`;
- abrir `http://localhost:8501`;
- generar `VALIDACION_POC.md`.

Impacto: altisimo. La gente entiende el proyecto en video sin leer nada.

### 2. Anadir explicabilidad visual por evento

Ahora ya tienes `behavioral_factors`. Falta que el dashboard los venda.

Cambios:

- columna "Porque salto";
- chips: `scan_ports_60s`, `dns_query_shape`, `http_payload_shape`, `volume_spike`;
- separacion visual entre `raw_score` y `behavioral_boost`;
- tooltip o panel lateral con "IA raw + boost + Suricata".

Impacto: hace que parezca producto, no script.

### 3. Generar una matriz de validacion bonita

`scripts/validate-poc.ps1` ya existe. Convierte su resultado en una tabla mas potente:

- benign control;
- 5 ataques;
- max raw score;
- max final score;
- factor esperado;
- alerta Suricata esperada;
- PASS/FAIL;
- comando exacto y timestamp.

Impacto: sube credibilidad tecnica. LinkedIn premia demos, pero los recruiters tecnicos buscan evidencia.

### 4. Modelo con tarjeta tecnica

Crear `model/MODEL_CARD.md`:

- algoritmo;
- version River;
- features principales;
- dataset sintetico;
- threshold;
- limitaciones;
- que NO promete;
- como reproducir.

Impacto: demuestra madurez. Evita que parezca "he pegado una IA".

### 5. Limpiar artefactos y fijar versiones

Hacer el repo mas profesional:

- quitar/ignorar community rules descargadas;
- no publicar pickle salvo release artifact;
- pin de dependencias;
- pin de imagenes Docker;
- eliminar fallbacks legacy del dashboard;
- reemplazar `Invoke-Expression`.

Impacto: menos ruido, mas confianza.

### 6. Grabar un GIF/video con narrativa clara

Estructura del post:

1. "Trafico normal: baseline estable".
2. "Inyecto port scan".
3. "Zeek extrae features".
4. "Suricata confirma firma".
5. "IA sube score y explica factor".
6. "El aprendizaje se bloquea para evitar poisoning".

Frase fuerte:

> "No queria un dashboard bonito sobre logs muertos: queria un mini NDR local, reproducible y explicable."

## Plan recomendado en orden

1. Limpiar repo:
   - ignorar `suricata/lib/rules/*`;
   - decidir si `model/meta.json` se publica o se regenera;
   - quitar fallbacks legacy del dashboard si ya no se usan.

2. Reproducibilidad:
   - pin de Python deps;
   - pin de Docker images;
   - guardar version River en `meta.json`;
   - anadir `feature_schema_hash`.

3. Seguridad/calidad:
   - reemplazar `Invoke-Expression`;
   - quitar CORS abierto;
   - sustituir `innerHTML` por `textContent`.

4. Validacion:
   - asegurar que `scripts/validate-poc.ps1` corre end-to-end;
   - ampliar `VALIDACION_POC.md` con raw vs final score;
   - guardar evidencia de la ultima validacion.

5. Wow:
   - `demo-linkedin.ps1`;
   - dashboard con explicabilidad;
   - video/GIF y README con capturas.

## Prioridad de borrado

### Borrar o sacar del repo

- `suricata/lib/rules/suricata.rules`
- `suricata/lib/rules/classification.config`
- cualquier `__pycache__/`
- cualquier PCAP real generado en `data/`
- cualquier log Zeek/Suricata generado en `logs/`
- cualquier JSONL temporal en `output/`
- modelos `.bak`, `.tmp`, `model_smoke.pkl`, `model_eval.pkl`, `meta_smoke.json`, `meta_eval.json`

### Mantener

- `suricata/etc/local.rules`
- `suricata/etc/suricata.yaml`
- `suricata/etc/classification.config`
- `.gitkeep` en dirs vacios
- scripts de validacion y limpieza
- `pipeline/anomaly_utils.py`, aunque conviene documentar que es parte del scoring hibrido

### Dudoso: decidir estrategia

- `model/model.pkl`: mantener localmente para operar; no versionar.
- `model/meta.json`: si se publica, convertirlo en evidencia reproducible; si no, regenerarlo siempre.

## Hallazgos por archivo

- `.gitignore`: bien para data/logs/output/model, pero falta cubrir `suricata/lib/rules/*`.
- `requirements.txt`: demasiado abierto; fijar versiones.
- `docker-compose.yml`: `zeek/zeek:lts` y `jasonish/suricata:latest` son flotantes.
- `scripts/poc-train.ps1`: funcional, pero usa `Invoke-Expression`.
- `scripts/poc-watcher.ps1`: funcional, pero usa `Invoke-Expression`; buena idea el lock file.
- `scripts/poc-live.ps1`: borra directorios con `.gitkeep`; cambiar a limpieza de contenido.
- `scripts/validate-poc.ps1`: buena base de validacion; mejorar eficiencia y ampliar reporte.
- `scripts/clean-repo.ps1`: util; contiene restos legacy aceptables si se documentan.
- `pipeline/build_features.py`: buena cobertura de features; `except Exception` en `num()` es amplio pero pragmatico.
- `pipeline/train_baseline.py`: enfoque correcto; falta versionado de schema/deps en meta.
- `pipeline/score.py`: buena proteccion anti-poisoning; revisar `learn_below=0.0`.
- `pipeline/anomaly_utils.py`: util para demo, pero convierte el sistema en hibrido; documentarlo claramente.
- `pipeline/suricata_utils.py`: simple y util; ajustar si las firmas reales generan falsos positivos.
- `simulation/common.py`: muy completo para PoC; contiene pequena redundancia en `NORMAL_BUILDERS`.
- `dashboard/api.py`: util, pero CORS abierto y fallbacks legacy.
- `dashboard/script.js`: visualmente eficaz, pero usar `textContent` en vez de `innerHTML`.
- `dashboard/index.html`: buen impacto visual; evitar dependencia CDN si quieres demo robusta.
- `dashboard/style.css`: cumple para demo; revisar mobile si se graba desde pantalla pequena.

## Fuentes externas consultadas

- River HalfSpaceTrees docs: https://riverml.xyz/latest/api/anomaly/HalfSpaceTrees/
