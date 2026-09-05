import hashlib
import sys
import os

def calcular_sha256(ruta_archivo):
    """
    Calcula el hash SHA-256 de un archivo procesándolo en bloques de 64 KB
    para garantizar eficiencia en archivos de gran tamaño.
    """
    hash_sha256 = hashlib.sha256()
   
    if not os.path.exists(ruta_archivo):
        print(f"[!] Error: El archivo '{ruta_archivo}' no existe.")
        return None

    try:
        with open(ruta_archivo, "rb") as archivo:
            # Leer en bloques de 65,536 bytes (64 KB)
            for bloque in iter(lambda: archivo.read(65536), b""):
                hash_sha256.update(bloque)
        return hash_sha256.hexdigest()
    except Exception as e:
        print(f"[!] Error al procesar el archivo: {e}")
        return None

if __name__ == "__main__":
    # Nombre del archivo por defecto o pasado por argumento
    archivo_objetivo = sys.argv[1] if len(sys.argv) > 1 else "evidencia_original.txt"
   
    print("=" * 60)
    print("   SISTEMA DE GENERACIÓN DE HASH FORENSE (SHA-256)")
    print("=" * 60)
   
    hash_resultado = calcular_sha256(archivo_objetivo)
   
    if hash_resultado:
        print(f"Archivo analizado : {archivo_objetivo}")
        print(f"Algoritmo         : SHA-256")
        print(f"Hash Calculado    : {hash_resultado}")
        print("=" * 60)
