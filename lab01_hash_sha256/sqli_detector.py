import re
from collections import defaultdict

# Patrones comunes de SQL Injection
PATRONES_SQLi = {
    "Union-based": [
        r"union\s+select", r"union\s+all\s+select", r"union\s+distinct\s+select"
    ],
    "Error-based": [
        r"extractvalue\s*\(", r"updatexml\s*\(", r"geometrycollection", r"\[SQL Server\]", r"ODBC"
    ],
    "Boolean-based Blind": [
        r"or\s+1\s*=\s*1", r"or\s+'1'\s*=\s*'1", r"and\s+1\s*=\s*1", r"and\s+1\s*=\s*2"
    ],
    "Time-based Blind": [
        r"sleep\s*\(", r"benchmark\s*\(", r"waitfor\s+delay", r"pg_sleep"
    ],
    "Stacked Queries": [
        r";\s*drop\s+table", r";\s*delete\s+from", r";\s*update\s+", r";\s*insert\s+into"
    ],
    "Comment / Bypass": [
        r"--\s*\( ", r"#\s* \)", r"/\*.*\*/", r"or\s+'a'\s*=\s*'a"
    ]
}

def detectar_sqli(ruta_log):
    print("=" * 80)
    print("     DETECTOR FORENSE DE INTENTOS DE SQL INJECTION")
    print("=" * 80)

    try:
        with open(ruta_log, "r", encoding="utf-8", errors="ignore") as f:
            lineas = f.readlines()
    except FileNotFoundError:
        print(f"[!] Error: El archivo '{ruta_log}' no existe.")
        return

    hallazgos = []
    contador_tipos = defaultdict(int)

    for num, linea in enumerate(lineas, 1):
        linea_lower = linea.lower().strip()
        tipos_detectados = []

        for tipo, patrones in PATRONES_SQLi.items():
            for patron in patrones:
                if re.search(patron, linea_lower, re.IGNORECASE):
                    tipos_detectados.append(tipo)
                    contador_tipos[tipo] += 1
                    break  # Evita contar el mismo tipo varias veces por línea

        if tipos_detectados:
            # Extraer posible IP
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', linea)
            ip = ip_match.group(0) if ip_match else "Desconocida"

            # Calcular riesgo
            riesgo = 0
            if "Union-based" in tipos_detectados: riesgo += 4
            if "Error-based" in tipos_detectados: riesgo += 3
            if "Time-based Blind" in tipos_detectados: riesgo += 5
            if "Stacked Queries" in tipos_detectados: riesgo += 5
            if "Boolean-based Blind" in tipos_detectados: riesgo += 3
            if "Comment / Bypass" in tipos_detectados: riesgo += 2

            if riesgo >= 8:
                nivel = "CRÍTICO"
            elif riesgo >= 5:
                nivel = "ALTO"
            elif riesgo >= 3:
                nivel = "MEDIO"
            else:
                nivel = "BAJO"

            hallazgos.append({
                "linea": num,
                "ip": ip,
                "tipos": list(set(tipos_detectados)),
                "riesgo": riesgo,
                "nivel": nivel,
                "payload": linea.strip()[:120] + ("..." if len(linea) > 120 else "")
            })

    # Ordenar por mayor riesgo
    hallazgos.sort(key=lambda x: x["riesgo"], reverse=True)

    if not hallazgos:
        print("No se detectaron posibles intentos de SQL Injection.")
        print("=" * 80)
        return

    print(f"{'LÍNEA':<8} | {'IP':<16} | {'RIESGO':<8} | {'NIVEL':<10} | TIPOS DETECTADOS")
    print("-" * 80)

    for h in hallazgos:
        tipos_str = ", ".join(h["tipos"])
        print(f"{h['linea']:<8} | {h['ip']:<16} | {h['riesgo']:<8} | {h['nivel']:<10} | {tipos_str}")

    print("-" * 80)
    print("\nResumen por tipo de SQLi:")
    for tipo, cantidad in sorted(contador_tipos.items(), key=lambda x: x[1], reverse=True):
        print(f"  • {tipo:<25} → {cantidad} detección(es)")

    print("-" * 80)
    print(f"Total de posibles intentos detectados: {len(hallazgos)}")
    print("=" * 80)

if __name__ == "__main__":
    detectar_sqli("access.log")  # Cambia el nombre del archivo si es necesario