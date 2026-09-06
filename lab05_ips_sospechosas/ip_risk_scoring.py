import re
from collections import defaultdict

# Configuración
UMBRAL_ALTO_TRAFICO = 5
IP_MALICIOSAS = ["192.168.1.250", "45.33.32.156", "23.197.170.165"]

# Palabras clave que aumentan el riesgo
PALABRAS_ATAQUE = {
    "escaneo": 3,
    "scan": 3,
    "login": 2,
    "unauthorized": 3,
    "passwd": 4,
    "privilegios": 4,
    "c2": 5,
    "sospechosa": 2,
    "fallido": 2
}

def analizar_riesgo_ips(ruta_log):
    print("=" * 75)
    print("     SISTEMA DE PUNTUACIÓN DE RIESGO DE IPs (FORENSE DIGITAL)")
    print("=" * 75)

    try:
        with open(ruta_log, "r", encoding="utf-8") as f:
            lineas = f.readlines()
    except FileNotFoundError:
        print(f"[!] Error: El archivo '{ruta_log}' no existe.")
        return

    # Estructura: ip → {conteo, score, motivos}
    datos_ips = defaultdict(lambda: {"conteo": 0, "score": 0, "motivos": []})

    patron_ip = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    for linea in lineas:
        ips = re.findall(patron_ip, linea)
        linea_lower = linea.lower()

        for ip in ips:
            datos_ips[ip]["conteo"] += 1

            # Puntos por lista negra
            if ip in IP_MALICIOSAS and "Lista Negra" not in datos_ips[ip]["motivos"]:
                datos_ips[ip]["score"] += 6
                datos_ips[ip]["motivos"].append("Lista Negra (IoC)")

            # Puntos por palabras clave de ataque
            for palabra, puntos in PALABRAS_ATAQUE.items():
                if palabra in linea_lower and palabra not in " ".join(datos_ips[ip]["motivos"]).lower():
                    datos_ips[ip]["score"] += puntos
                    datos_ips[ip]["motivos"].append(f"Keyword: {palabra}")

    # Puntos por alto volumen
    for ip, data in datos_ips.items():
        if data["conteo"] >= UMBRAL_ALTO_TRAFICO:
            data["score"] += 3
            data["motivos"].append(f"Alto tráfico ({data['conteo']} peticiones)")

    # Ordenar por score de mayor a menor
    ips_ordenadas = sorted(datos_ips.items(), key=lambda x: x[1]["score"], reverse=True)

    print(f"{'IP':<18} | {'PETICIONES':<11} | {'RIESGO':<8} | {'NIVEL':<10} | MOTIVOS")
    print("-" * 75)

    for ip, data in ips_ordenadas:
        score = data["score"]
        if score >= 10:
            nivel = "CRÍTICO"
        elif score >= 6:
            nivel = "ALTO"
        elif score >= 3:
            nivel = "MEDIO"
        else:
            nivel = "BAJO"

        motivos = " | ".join(data["motivos"]) if data["motivos"] else "Ninguno"
        print(f"{ip:<18} | {data['conteo']:<11} | {score:<8} | {nivel:<10} | {motivos}")

    print("-" * 75)
    print("=" * 75)

if __name__ == "__main__":
    analizar_riesgo_ips("registro_trafico.log")
