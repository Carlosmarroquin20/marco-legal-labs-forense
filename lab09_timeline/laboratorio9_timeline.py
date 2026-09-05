from datetime import datetime

# Simulación de fuentes de logs heterogéneas
LOGS_FIREWALL = [
    {"timestamp": "2026-08-15 08:01:05", "fuente": "FIREWALL", "evento": "Conexión entrante sospechosa desde IP 45.33.32.156:443"},
    {"timestamp": "2026-08-15 08:02:10", "fuente": "FIREWALL", "evento": "Escaneo de puertos detectado desde IP 192.168.1.250"}
]

LOGS_WEB = [
    {"timestamp": "2026-08-15 08:02:13", "fuente": "WEB_SERVER", "evento": "POST /admin/login HTTP/1.1 401 Unauthorized (Usuario: admin)"},
    {"timestamp": "2026-08-15 08:02:15", "fuente": "WEB_SERVER", "evento": "GET /etc/passwd HTTP/1.1 404 Not Found"}
]

LOGS_SISTEMA = [
    {"timestamp": "2026-08-15 08:02:20", "fuente": "SYS_LOG", "evento": "Intento de elevación de privilegios fallido en usuario 'www-data'"},
    {"timestamp": "2026-08-15 08:03:00", "fuente": "SYS_LOG", "evento": "Conexión saliente C2 establecida hacia 23.197.170.165"}
]

def consolidar_linea_tiempo():
    todos_los_eventos = LOGS_FIREWALL + LOGS_WEB + LOGS_SISTEMA
   
    # Ordenar por timestamp
    eventos_ordenados = sorted(
        todos_los_eventos,
        key=lambda x: datetime.strptime(x["timestamp"], "%Y-%m-%d %H:%M:%S")
    )

    print("=========================================================================")
    print("    RECONSTRUCCIÓN CRONOLÓGICA DEL INCIDENTE DE SEGURIDAD (LAB 9)")
    print("=========================================================================")
    print(f"{'FECHA Y HORA':<20} | {'FUENTE':<12} | {'DESCRIPCIÓN DEL EVENTO'}")
    print("-------------------------------------------------------------------------")

    for e in eventos_ordenados:
        print(f"{e['timestamp']:<20} | {e['fuente']:<12} | {e['evento']}")

    print("=========================================================================")

if __name__ == "__main__":
    consolidar_linea_tiempo()
