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

def construir_timeline():
    todos = LOGS_FIREWALL + LOGS_WEB + LOGS_SISTEMA
    return sorted(todos, key=lambda x: datetime.strptime(x["timestamp"], "%Y-%m-%d %H:%M:%S"))

def analizar_incidente(eventos):
    etapas = {
        "reconocimiento": False,
        "fuerza_bruta": False,
        "explotacion": False,
        "escalada": False,
        "c2": False
    }

    for e in eventos:
        evento = e["evento"].lower()
        if "escaneo" in evento or "sospechosa" in evento:
            etapas["reconocimiento"] = True
        if "401 unauthorized" in evento or "login" in evento:
            etapas["fuerza_bruta"] = True
        if "/etc/passwd" in evento or "404" in evento:
            etapas["explotacion"] = True
        if "elevación de privilegios" in evento or "www-data" in evento:
            etapas["escalada"] = True
        if "c2" in evento or "conexión saliente" in evento:
            etapas["c2"] = True

    return etapas

def generar_conclusion(etapas):
    detectadas = [k for k, v in etapas.items() if v]
    total = len(detectadas)

    print("\n" + "="*70)
    print("           ANÁLISIS AUTOMÁTICO DEL INCIDENTE")
    print("="*70)

    if total == 0:
        print("No se detectaron indicadores claros de compromiso.")
        return

    print("Etapas del ataque detectadas:")
    nombres = {
        "reconocimiento": "• Reconocimiento / Escaneo",
        "fuerza_bruta": "• Intentos de fuerza bruta / acceso",
        "explotacion": "• Intentos de explotación (LFI/Path Traversal)",
        "escalada": "• Escalada de privilegios",
        "c2": "• Comunicación con servidor C2"
    }

    for etapa in detectadas:
        print(nombres[etapa])

    print("-"*70)
    if total >= 4:
        print("CONCLUSIÓN: Posible compromiso avanzado (Ataque multi-etapa)")
        print("Nivel de riesgo: CRÍTICO")
    elif total >= 2:
        print("CONCLUSIÓN: Actividad maliciosa confirmada")
        print("Nivel de riesgo: ALTO")
    else:
        print("CONCLUSIÓN: Actividad sospechosa detectada")
        print("Nivel de riesgo: MEDIO")
    print("="*70)

if __name__ == "__main__":
    print("="*70)
    print("   CORRELACIÓN DE LOGS + DETECCIÓN DE CADENA DE ATAQUE")
    print("="*70)

    timeline = construir_timeline()

    print(f"{'FECHA Y HORA':<20} | {'FUENTE':<12} | {'EVENTO'}")
    print("-"*70)
    for e in timeline:
        print(f"{e['timestamp']:<20} | {e['fuente']:<12} | {e['evento']}")

    etapas = analizar_incidente(timeline)
    generar_conclusion(etapas)
