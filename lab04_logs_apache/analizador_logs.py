import re
import sys
import os

# Patrones Regex para detección de ataques web
PATRONES_ATAQUE = {
    "Inyeccion SQL (SQLi)": r"(?i)(UNION\s+SELECT|' OR '1'='1|SELECT.*FROM|DROP\s+TABLE|INSERT\s+INTO)",
    "Cross-Site Scripting (XSS)": r"(?i)(<script>|javascript:|onerror=|onload=)",
    "Path Traversal": r"(?i)(\.\./\.\./|/etc/passwd|windows/win.ini)"
}

def analizar_log_apache(ruta_log):
    if not os.path.exists(ruta_log):
        print(f"[!] Error: El archivo de log '{ruta_log}' no existe.")
        return

    # Expresión regular para parsear registros de log Apache
    log_regex = r'(\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(.*?)\]\s+"(GET|POST|PUT|DELETE)\s+(.*?)\s+HTTP/.*?"\s+(\d+)\s+(\d+|-)'

    total_registros = 0
    hallazgos = []

    with open(ruta_log, "r", encoding="utf-8", errors="ignore") as archivo:
        for num_linea, linea in enumerate(archivo, start=1):
            total_registros += 1
            coincidencia = re.search(log_regex, linea)
           
            peticion_analizar = linea
            ip_origen = "Desconocida"
           
            if coincidencia:
                ip_origen = coincidencia.group(1)
                peticion_analizar = coincidencia.group(4)

            # Evaluar peticiones sospechosas contra los patrones de ataque
            for tipo_ataque, patron in PATRONES_ATAQUE.items():
                if re.search(patron, peticion_analizar):
                    hallazgos.append({
                        "linea": num_linea,
                        "ip": ip_origen,
                        "tipo": tipo_ataque,
                        "contenido": linea.strip()
                    })

    # Despliegue de Resultados Forenses
    print("=" * 75)
    print("      SISTEMA FORENSE DE ANÁLISIS DE LOGS WEB APACHE")
    print("=" * 75)
    print(f"Archivo analizado   : {ruta_log}")
    print(f"Total de registros  : {total_registros}")
    print(f"Amenazas detectadas : {len(hallazgos)}")
    print("-" * 75)

    if hallazgos:
        for h in hallazgos:
            print(f"[ALERTA DETECTADA - Línea {h['linea']}]")
            print(f"  * IP Origen : {h['ip']}")
            print(f"  * Categoria : {h['tipo']}")
            print(f"  * Registro  : {h['contenido']}")
            print("-" * 75)
    else:
        print("[STATUS: OK] No se detectaron patrones de ataques en los logs.")
   
    print("=" * 75)

if __name__ == "__main__":
    archivo_log = sys.argv[1] if len(sys.argv) > 1 else "access.log"
    analizar_log_apache(archivo_log)
