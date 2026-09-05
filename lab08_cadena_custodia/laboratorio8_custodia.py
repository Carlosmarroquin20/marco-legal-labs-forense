import hashlib
import os
import json
from datetime import datetime

PERITO_RESPONSABLE = "Analista Forense"

def calcular_hashes_duales(ruta_archivo):
    hash_md5 = hashlib.md5()
    hash_sha256 = hashlib.sha256()

    with open(ruta_archivo, "rb") as f:
        for bloque in iter(lambda: f.read(4096), b""):
            hash_md5.update(bloque)
            hash_sha256.update(bloque)

    return hash_md5.hexdigest(), hash_sha256.hexdigest()

def registrar_cadena_custodia(ruta_evidencia):
    print("=========================================================================")
    print("      SISTEMA AUTOMATIZADO DE CADENA DE CUSTODIA FORENSE (LAB 8)")
    print("=========================================================================")

    if not os.path.exists(ruta_evidencia):
        print(f"[!] Error: La evidencia '{ruta_evidencia}' no existe.")
        return

    stats = os.stat(ruta_evidencia)
    md5_val, sha256_val = calcular_hashes_duales(ruta_evidencia)
    fecha_registro = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    acta_custodia = {
        "id_evidencia": f"EVID-{int(datetime.now().timestamp())}",
        "archivo_origen": os.path.basename(ruta_evidencia),
        "ruta_absoluta": os.path.abspath(ruta_evidencia),
        "tamano_bytes": stats.st_size,
        "custodio_responsable": PERITO_RESPONSABLE,
        "fecha_ingreso_custodia": fecha_registro,
        "hashes_integridad": {
            "MD5": md5_val,
            "SHA256": sha256_val
        },
        "estado_integridad": "INTACTA / VERIFICADA"
    }

    # Guardar acta de custodia en JSON
    nombre_acta = f"cadena_custodia_{os.path.basename(ruta_evidencia)}.json"
    with open(nombre_acta, "w", encoding="utf-8") as f:
        json.dump(acta_custodia, f, indent=4, ensure_ascii=False)

    print(f"[*] ID de Evidencia : {acta_custodia['id_evidencia']}")
    print(f"[*] Archivo         : {acta_custodia['archivo_origen']}")
    print(f"[*] Tamaño          : {acta_custodia['tamano_bytes']} bytes")
    print(f"[*] Custodio        : {acta_custodia['custodio_responsable']}")
    print(f"[*] Hash MD5        : {md5_val}")
    print(f"[*] Hash SHA-256    : {sha256_val}")
    print("-------------------------------------------------------------------------")
    print(f"[+] Acta de cadena de custodia generada exitosamente: '{nombre_acta}'")
    print("=========================================================================")

if __name__ == "__main__":
    registrar_cadena_custodia("evidencia_foto.jpg")
