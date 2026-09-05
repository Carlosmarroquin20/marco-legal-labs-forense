import os
import time

EXTENSION_RANSOMWARE = ".locked"

def simular_analisis_ransomware(directorio_trabajo):
    print("=========================================================================")
    print("   ANÁLISIS DE COMPORTAMIENTO Y DETECCIÓN DE RANSOMWARE (LAB 10)")
    print("=========================================================================")

    if not os.path.exists(directorio_trabajo):
        os.makedirs(directorio_trabajo)
        # Crear archivos de prueba
        for i in range(1, 4):
            with open(os.path.join(directorio_trabajo, f"documento_{i}.txt"), "w") as f:
                f.write("Información confidencial de la organización.")

    print(f"[*] Inspeccionando directorio objetivo: '{directorio_trabajo}'")
   
    archivos = os.listdir(directorio_trabajo)
    archivos_comprometidos = []

    # Simulación de detección
    for archivo in archivos:
        ruta_completa = os.path.join(directorio_trabajo, archivo)
        if archivo.endswith(EXTENSION_RANSOMWARE) or "READ_ME" in archivo:
            archivos_comprometidos.append(archivo)

    print("-------------------------------------------------------------------------")
    if archivos_comprometidos:
        print("[ALERTA CRÍTICA] Patrón de Ransomware Detectado:")
        for ac in archivos_comprometidos:
            print(f"  -> Archivo alterado/nota de rescate: {ac}")
        print("\n[ACCION DE CONTENCIÓN]: Aislar el host de la red inmediatamente.")
    else:
        print("[OK] No se detectaron patrones de cifrado masivo ni notas de rescate.")
    print("=========================================================================")

if __name__ == "__main__":
    simular_analisis_ransomware("entorno_prueba_ransomware")
