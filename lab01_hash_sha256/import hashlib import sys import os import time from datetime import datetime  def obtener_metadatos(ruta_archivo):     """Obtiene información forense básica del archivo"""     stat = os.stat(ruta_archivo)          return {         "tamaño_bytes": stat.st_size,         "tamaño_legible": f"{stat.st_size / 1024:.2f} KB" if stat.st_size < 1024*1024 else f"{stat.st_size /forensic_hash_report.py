import hashlib
import sys
import os
import time
from datetime import datetime

def obtener_metadatos(ruta_archivo):
    """Obtiene información forense básica del archivo"""
    stat = os.stat(ruta_archivo)
    
    return {
        "tamaño_bytes": stat.st_size,
        "tamaño_legible": f"{stat.st_size / 1024:.2f} KB" if stat.st_size < 1024*1024 else f"{stat.st_size / (1024*1024):.2f} MB",
        "fecha_creacion": datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
        "fecha_modificacion": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "fecha_acceso": datetime.fromtimestamp(stat.st_atime).strftime("%Y-%m-%d %H:%M:%S"),
    }

def calcular_sha256(ruta_archivo):
    """Calcula el hash SHA-256 leyendo el archivo por bloques"""
    hash_sha256 = hashlib.sha256()
    
    with open(ruta_archivo, "rb") as archivo:
        for bloque in iter(lambda: archivo.read(65536), b""):
            hash_sha256.update(bloque)
    
    return hash_sha256.hexdigest()

def generar_reporte(ruta_archivo, hash_resultado, metadatos):
    """Genera y guarda un reporte forense"""
    nombre_reporte = f"reporte_forense_{os.path.basename(ruta_archivo)}.txt"
    
    contenido = f"""============================================================
         REPORTE FORENSE DE INTEGRIDAD DE EVIDENCIA
============================================================
Fecha del análisis : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Archivo analizado  : {ruta_archivo}
------------------------------------------------------------
METADATOS DEL ARCHIVO
------------------------------------------------------------
Tamaño             : {metadatos['tamaño_legible']} ({metadatos['tamaño_bytes']} bytes)
Fecha de creación  : {metadatos['fecha_creacion']}
Última modificación: {metadatos['fecha_modificacion']}
Último acceso      : {metadatos['fecha_acceso']}
------------------------------------------------------------
HASH DE INTEGRIDAD
------------------------------------------------------------
Algoritmo          : SHA-256
Hash               : {hash_resultado}
============================================================
"""
    
    with open(nombre_reporte, "w", encoding="utf-8") as f:
        f.write(contenido)
    
    return nombre_reporte, contenido

if __name__ == "__main__":
    archivo_objetivo = sys.argv[1] if len(sys.argv) > 1 else "evidencia_original.txt"
    
    print("=" * 60)
    print("   GENERADOR DE REPORTE FORENSE + HASH SHA-256")
    print("=" * 60)
    
    if not os.path.exists(archivo_objetivo):
        print(f"[!] Error: El archivo '{archivo_objetivo}' no existe.")
        sys.exit(1)
    
    try:
        hash_resultado = calcular_sha256(archivo_objetivo)
        metadatos = obtener_metadatos(archivo_objetivo)
        nombre_reporte, contenido = generar_reporte(archivo_objetivo, hash_resultado, metadatos)
        
        print(contenido)
        print(f"[+] Reporte guardado como: {nombre_reporte}")
        
    except Exception as e:
        print(f"[!] Error al procesar el archivo: {e}")
