# Laboratorios Técnicos — Proyecto Final Marco Legal y Regulatorio

Repositorio con el código fuente de los 10 laboratorios de análisis forense e
informática desarrollados para el Capítulo VI del proyecto final del curso
**Marco Legal y Regulatorio**, Maestría en Seguridad Informática (MASI),
Universidad Mariano Gálvez de Guatemala.

El documento completo describe, para cada laboratorio, el objetivo, la
metodología, las herramientas utilizadas, la evidencia de ejecución (capturas
de pantalla) y el dictamen técnico. Este repositorio contiene únicamente el
**código fuente** referenciado en los Anexos del Capítulo VI, para no
extender innecesariamente el documento entregado.

## Estructura

| Carpeta | Laboratorio | Archivo principal |
|---|---|---|
| `lab01_hash_sha256/` | Lab 1 — Cálculo de Hash SHA-256 | `generar_hash.py` |
| `lab02_verificar_integridad/` | Lab 2 — Verificación de integridad de evidencia digital | `verificar_integridad.py` |
| `lab03_deteccion_modificacion/` | Lab 3 — Detección de modificación de archivos | `monitor_integridad.py` |
| `lab04_logs_apache/` | Lab 4 — Análisis de logs Apache | `analizador_logs.py` + `access.log` (log de prueba) |
| `lab05_ips_sospechosas/` | Lab 5 — Detección de IPs sospechosas | `detectar_ips.py` |
| `lab06_sql_injection/` | Lab 6 — Demostración controlada de inyección SQL (SQLi) | `laboratorio6_sqli.py` |
| `lab07_metadatos_exif/` | Lab 7 — Extracción de metadatos y evidencia EXIF | `laboratorio7_metadatos.py` |
| `lab08_cadena_custodia/` | Lab 8 — Cadena de custodia automatizada | `laboratorio8_custodia.py` |
| `lab09_timeline/` | Lab 9 — Reconstrucción de línea de tiempo de un incidente | `laboratorio9_timeline.py` |
| `lab10_ransomware/` | Lab 10 — Análisis y detección de comportamiento de ransomware | `laboratorio10_ransomware.py` |

## Requisitos

- Python 3.10 o superior
- Los laboratorios 1 al 6, 8, 9 y 10 usan únicamente librerías estándar de Python
  (`hashlib`, `os`, `sys`, `re`, `json`, `datetime`, `sqlite3`, `time`).
- El laboratorio 7 (metadatos EXIF) requiere la librería `Pillow`:

  ```bash
  pip install Pillow
  ```

## Ejecución

Cada script se ejecuta de forma independiente desde su carpeta, por ejemplo:

```bash
cd lab06_sql_injection
python laboratorio6_sqli.py
```

Los laboratorios 4 y 5 esperan un archivo de log como entrada
(`access.log`, incluido en `lab04_logs_apache/` como dato de prueba).

## Nota académica

El código fue desarrollado con fines demostrativos y educativos, en entornos
controlados y con datos de prueba (usuarios, IPs y archivos ficticios). No
está destinado a uso en sistemas de producción ni contiene información real
de ninguna organización.

## Referencia

Documento completo: *"Análisis de la regulación penal de los delitos
informáticos en Guatemala y propuesta de actualización del Código Penal
frente a las amenazas emergentes en ciberseguridad"* — Capítulo VI,
Desarrollo Técnico.
