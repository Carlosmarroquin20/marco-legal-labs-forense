import os
from datetime import datetime
from PIL import Image
from PIL.ExifTags import TAGS

def obtener_fechas_sistema(ruta_archivo):
    # Obtención de MAC Times (Modified, Accessed, Created)
    stats = os.stat(ruta_archivo)
    creacion = datetime.fromtimestamp(stats.st_ctime)
    modificacion = datetime.fromtimestamp(stats.st_mtime)
    acceso = datetime.fromtimestamp(stats.st_atime)
    tamano = stats.st_size / 1024 # Convertir a KB
   
    print("============================================================")
    print(" [1] METADATOS DEL SISTEMA DE ARCHIVOS (MAC TIMES) ")
    print("============================================================")
    print(f" Archivo Analizado : {ruta_archivo}")
    print(f" Tamaño del Archivo: {tamano:.2f} KB")
    print(f" Creación (C)      : {creacion}")
    print(f" Modificación (M)  : {modificacion}")
    print(f" Último Acceso (A) : {acceso}")

def extraer_exif(ruta_imagen):
    print("\n============================================================")
    print(" [2] METADATOS INCRUSTADOS (EXIF - ATRIBUTOS INTERNOS) ")
    print("============================================================")
    try:
        imagen = Image.open(ruta_imagen)
        exif_data = imagen._getexif()
       
        if not exif_data:
            print(" [!] No se encontraron metadatos EXIF en este archivo.")
            return

        print(" [+] Extracción de metadatos relevantes (Hardware/Software):")
        tags_interes = ['Make', 'Model', 'DateTimeOriginal', 'Software', 'GPSInfo']
        encontrados = 0
       
        for tag_id, valor in exif_data.items():
            tag_nombre = TAGS.get(tag_id, tag_id)
            if tag_nombre in tags_interes:
                print(f"  -> {tag_nombre:<18}: {valor}")
                encontrados += 1
               
        if encontrados == 0:
            print("  [-] No se detectó información de Cámara, Software o GPS.")
           
    except Exception as e:
        print(f" [X] Error procesando imagen: {e}")

if __name__ == '__main__':
    archivo_evidencia = "evidencia_foto.jpg"
   
    print("\nHERRAMIENTA FORENSE DE EXTRACCIÓN DE METADATOS")
    if os.path.exists(archivo_evidencia):
        obtener_fechas_sistema(archivo_evidencia)
        extraer_exif(archivo_evidencia)
        print("\n[OK] Extracción finalizada con éxito.")
    else:
        print(f"\n[!] Error: Archivo '{archivo_evidencia}' no encontrado.")
        print("Por favor, coloca una fotografía real con el nombre 'evidencia_foto.jpg' en esta carpeta.")
