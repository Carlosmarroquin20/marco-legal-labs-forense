import re
from collections import Counter

# Umbral de peticiones para considerar una IP como sospechosa por frecuencia
UMBRAL_PETICIONES = 5

# Lista de Indicadores de Compromiso (IoCs) - Lista Negra de IPs
IP_MALICIOSAS_CONOCIDAS = ["192.168.1.250", "45.33.32.156", "23.197.170.165"]

def analizar_ips(ruta_log):
    print("=" * 70)
    print("     SISTEMA DE DETECCIÓN DE IP SOSPECHOSAS (FORENSE DIGITAL)")
    print("=" * 70)
   
    try:
        with open(ruta_log, "r", encoding="utf-8") as f:
            contenido = f.read()
    except FileNotFoundError:
        print(f"[!] Error: El archivo '{ruta_log}' no existe.")
        return

    # Expresión regular para extraer direcciones IPv4
    patron_ip = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips_encontradas = re.findall(patron_ip, contenido)
   
    conteo_ips = Counter(ips_encontradas)
   
    print(f"Total de direcciones IP analizadas: {len(ips_encontradas)}")
    print(f"Direcciones IP únicas identificadas : {len(conteo_ips)}")
    print("-" * 70)
    print(f"{'DIRECCIÓN IP':<20} | {'PETICIONES':<12} | {'ESTADO / DIAGNÓSTICO'}")
    print("-" * 70)

    hallazgos = 0
    for ip, cantidad in conteo_ips.most_common():
        motivos = []
       
        if cantidad >= UMBRAL_PETICIONES:
            motivos.append(f"Alto volumen de tráfico (>= {UMBRAL_PETICIONES})")
           
        if ip in IP_MALICIOSAS_CONOCIDAS:
            motivos.append("Coincidencia con Lista Negra (IoC)")

        if motivos:
            hallazgos += 1
            diagnostico = " | ".join(motivos)
            print(f"{ip:<20} | {cantidad:<12} | [ALERTA] {diagnostico}")
        else:
            print(f"{ip:<20} | {cantidad:<12} | [OK] Tráfico Normal")

    print("-" * 70)
    print(f"Resumen: Se detectaron {hallazgos} IP(s) sospechosa(s).")
    print("=" * 70)

if __name__ == "__main__":
    analizar_ips("registro_trafico.log")
