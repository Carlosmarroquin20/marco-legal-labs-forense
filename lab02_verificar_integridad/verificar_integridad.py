import hashlib
import sys
import os

def verificar_integridad(ruta_archivo, hash_referencia):
    """
    Calcula el hash del archivo actual y lo compara con el hash
    original guardado en la cadena de custodia.
    """
    if not os.path.exists(ruta_archivo):
        print(f"[!] Error: El archivo '{ruta_archivo}' no existe.")
        return

    hash_sha256 = hashlib.sha256()
   
    with open(ruta_archivo, "rb") as archivo:
        for bloque in iter(lambda: archivo.read(65536), b""):
            hash_sha256.update(bloque)
           
    hash_actual = hash_sha256.hexdigest().lower()
    hash_ref_clean = hash_referencia.strip().lower()

    print("=" * 65)
    print("      SISTEMA DE VERIFICACIÓN DE INTEGRIDAD FORENSE")
    print("=" * 65)
    print(f"Archivo analizado : {ruta_archivo}")
    print(f"Hash Referencia   : {hash_ref_clean}")
    print(f"Hash Actual       : {hash_actual}")
    print("-" * 65)

    if hash_actual == hash_ref_clean:
        print("[STATUS: VÁLIDO]  El archivo mantiene su INTEGRIDAD. No ha sido alterado.")
    else:
        print("[STATUS: ALERTA] El archivo ha sido ALTERADO o CORROMPIDO.")
    print("=" * 65)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: py verificar_integridad.py <archivo> <hash_esperado>")
    else:
        verificar_integridad(sys.argv[1], sys.argv[2])
