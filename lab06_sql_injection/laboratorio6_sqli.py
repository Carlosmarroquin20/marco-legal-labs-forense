import sqlite3

def crear_base_datos():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE usuarios (id INTEGER PRIMARY KEY, usuario TEXT, password TEXT, rol TEXT)")
    cursor.execute("INSERT INTO usuarios VALUES (1, 'admin', 'SuperSecret2026!', 'Administrador')")
    cursor.execute("INSERT INTO usuarios VALUES (2, 'analista', 'Forense123', 'Analista')")
    cursor.execute("INSERT INTO usuarios VALUES (3, 'invitado', 'GuestPass', 'Usuario')")
    conn.commit()
    return conn

# Función Vulnerable: Concatenación directa
def login_vulnerable(conn, usuario, password):
    cursor = conn.cursor()
    query = f"SELECT * FROM usuarios WHERE usuario = '{usuario}' AND password = '{password}'"
    print(f"\n[QUERY EJECUTADA (VULNERABLE)]: {query}")
    cursor.execute(query)
    return cursor.fetchall()

# Función Mitigada: Prepared Statements
def login_seguro(conn, usuario, password):
    cursor = conn.cursor()
    query = "SELECT * FROM usuarios WHERE usuario = ? AND password = ?"
    print(f"\n[QUERY EJECUTADA (MITIGADA)]: {query} | Parámetros: ('{usuario}', '{password}')")
    cursor.execute(query, (usuario, password))
    return cursor.fetchall()

def ejecutar_laboratorio():
    conn = crear_base_datos()
    print("=========================================================================")
    print("   LABORATORIO 6: DEMOSTRACIÓN CONTROLADA DE ATAQUE SQL INJECTION (SQLi)")
    print("=========================================================================")
   
    payload_sqli = "' OR '1'='1"
    pass_cualquiera = "cualquiera"
   
    print("\n--- ESCENARIO 1: ATAQUE CONTRA APLICACIÓN VULNERABLE ---")
    res_vuln = login_vulnerable(conn, payload_sqli, pass_cualquiera)
    if res_vuln:
        print("[ALERTA] Explotación Exitosa: Autenticación evadida sin credenciales válidas.")
        for fila in res_vuln:
            print(f"  -> ID: {fila[0]} | Usuario: {fila[1]} | Password: {fila[2]} | Rol: {fila[3]}")
           
    print("\n--- ESCENARIO 2: ATAQUE CONTRA APLICACIÓN MITIGADA (PREPARED STATEMENTS) ---")
    res_seguro = login_seguro(conn, payload_sqli, pass_cualquiera)
    if not res_seguro:
        print("[OK] Ataque Bloqueado: La consulta parametrizada neutralizó la inyección.")
        print("Registros extraídos: 0 (Acceso denegado).")

if __name__ == "__main__":
    ejecutar_laboratorio()
