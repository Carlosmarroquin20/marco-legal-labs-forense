import hashlib
import os
import json
import sys

LINEA_BASE_FILE = "linea_base.json"

def calcular_hash_archivo(ruta):
    """Calcula el hash SHA-256 de un archivo dado."""
    hash_sha256 = hashlib.sha256()
    try:
        with open(ruta, "rb") as f:
            for bloque in iter(lambda: f.read(65536), b""):
                hash_sha256.update(bloque)
        return hash_sha256.hexdigest()
    except Exception:
        return None

def generar_linea_base(directorio):
    """Escanea el directorio y guarda el estado inicial de los archivos."""
    estado = {}
    for raiz, _, archivos in os.walk(directorio):
        for archivo in archivos:
            if archivo in [LINEA_BASE_FILE, "monitor_integridad.py"]:
                continue  # Omitir archivos del propio sistema de monitoreo
            ruta_completa = os.path.join(raiz, archivo)
            hash_val = calcular_hash_archivo(ruta_completa)
            if hash_val:
                estado[ruta_completa] = hash_val

    with open(LINEA_BASE_FILE, "w") as f:
        json.dump(estado, f, indent=4)
    print(f"[+] Línea base generada exitosamente en '{LINEA_BASE_FILE}' con {len(estado)} archivos.")

def auditar_directorio(directorio):
    """Compara el estado actual del directorio contra la línea base registrada."""
    if not os.path.exists(LINEA_BASE_FILE):
        print(f"[!] Error: No existe la línea base '{LINEA_BASE_FILE}'. Ejecute primero con '--init'.")
        return

    with open(LINEA_BASE_FILE, "r") as f:
        estado_base = json.load(f)

    estado_actual = {}
    for raiz, _, archivos in os.walk(directorio):
        for archivo in archivos:
            if archivo in [LINEA_BASE_FILE, "monitor_integridad.py"]:
                continue
            ruta_completa = os.path.join(raiz, archivo)
            hash_val = calcular_hash_archivo(ruta_completa)
            if hash_val:
                estado_actual[ruta_completa] = hash_val

    print("=" * 65)
    print("      SISTEMA DE DETECCIÓN DE MODIFICACIÓN DE ARCHIVOS")
    print("=" * 65)

    alteraciones = False

    # Detectar Modificados y Eliminados
    for ruta, hash_base in estado_base.items():
        if ruta not in estado_actual:
            print(f"[ELIMINADO]  El archivo ha sido borrado: {ruta}")
            alteraciones = True
        elif estado_actual[ruta] != hash_base:
            print(f"[MODIFICADO] El archivo ha sido alterado : {ruta}")
            alteraciones = True

    # Detectar Nuevos (Creados)
    for ruta in estado_actual:
        if ruta not in estado_base:
            print(f"[NUEVO]      Archivo nuevo no registrado : {ruta}")
            alteraciones = True

    if not alteraciones:
        print("[STATUS: OK] Ningún archivo ha sido modificado en el directorio.")
    print("=" * 65)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: py monitor_integridad.py <--init | --check>")
    elif sys.argv[1] == "--init":
        generar_linea_base(".")
    elif sys.argv[1] == "--check":
        auditar_directorio(".")
