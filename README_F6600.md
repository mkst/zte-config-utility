# Utilidad de Decriptado y Encriptado para ZTE ZXHN F6600

Herramienta optimizada para decodificar los archivos de respaldo `config.bin` descargados de los routers **ZTE ZXHN F6600** a formato XML legible, y volver a empaquetarlos/encriptarlos en archivos `.bin` 100% compatibles listos para subir al router.

---

## 🚀 Inicio Rápido

No necesitas activar manualmente el entorno virtual (`source ../bin/activate`), los scripts detectan el entorno de Python automáticamente.

### 1. Decriptar (de `.bin` a `.xml`)

```bash
# Decriptar especificando archivos:
./decrypt.sh mi_backup.bin salida.xml

# O indicando solo el archivo binario (genera mi_backup.xml automáticamente):
./decrypt.sh mi_backup.bin

# O sin argumentos (busca 'config.bin' y genera 'config.xml'):
./decrypt.sh
```

### 2. Encriptar (de `.xml` a `.bin`)

```bash
# Encriptar especificando archivos:
./encrypt.sh salida.xml config_modificado.bin

# O indicando solo el XML (genera salida_enc.bin automáticamente):
./encrypt.sh salida.xml

# O sin argumentos (busca 'config.xml' y genera 'config_enc.bin'):
./encrypt.sh
```

---

## 📋 Flujo de Trabajo Recomendado

```
+------------------+         ./decrypt.sh         +-------------------+
|    config.bin    | ---------------------------> |    config.xml     |
| (del router ZTE) |                              |   (XML legible)   |
+------------------+                              +-------------------+
                                                            |
                                                            | Editar configuraciones
                                                            v
+------------------+         ./encrypt.sh         +-------------------+
| config_mod.bin   | <--------------------------- | config_mod.xml    |
| (para el router) |                              |    (modificado)   |
+------------------+                              +-------------------+
```

1. **Descargar backup**: Entra en la interfaz web de tu router F6600 (*Administración / Gestión y Diagnóstico / Gestión de Configuración*) y descarga el archivo `config.bin`.
2. **Decriptar**: Ejecuta `./decrypt.sh config.bin config.xml`.
3. **Modificar**: Abre `config.xml` con un editor de texto (asegúrate de guardarlo en codificación UTF-8 y no romper etiquetas XML).
4. **Encriptar**: Ejecuta `./encrypt.sh config.xml config_nuevo.bin`.
5. **Subir al router**: Desde la misma sección de la interfaz web, restaura el archivo `config_nuevo.bin` y reinicia el router.

---

## ⚙️ Estructura de Archivos

- **[`decrypt.sh`](./decrypt.sh)**: Script ejecutable bash para decriptar.
- **[`encrypt.sh`](./encrypt.sh)**: Script ejecutable bash para encriptar.
- **[`f6600_tool.py`](./f6600_tool.py)**: Motor en Python que implementa toda la lógica criptográfica y de empaquetado del ZTE F6600 de forma autocontenida.
- **`../bin/python3`**: Intérprete de Python con las librerías necesarias (`pycryptodome`).

---

## 🔬 Especificaciones Técnicas del ZTE F6600

El ZTE F6600 utiliza un esquema de capas propietario estructurado de la siguiente forma:

| Capa | Componente | Descripción |
|---|---|---|
| **1** | **Cabecera ZTE** | 128 bytes. Magic `0x99999999, 0x44444444, 0x55555555, 0xAAAAAAAA`. Enteros en *Little-Endian* (`<28I`). Indica versión 2, longitud de cabecera 128 y tamaño del payload firmado. |
| **2** | **Firma del Router** | 12 bytes de cabecera con Magic `0x04030201` seguido de los bytes ASCII `F6600`. |
| **3** | **Cabecera Payload Exterior** | 60 bytes. Magic `0x01020304`, payload **Tipo 6** (cifrado AES-256-CBC). |
| **4** | **Cabecera de Chunks Cifrados** | 12 bytes (`dec_size`, `chunk_size`, `more_chunks`). |
| **5** | **Cifrado AES-256-CBC** | **Key String**: `D0BBC6C68676592e09a0`<br>**IV String**: `ZTE%FN$GponNJ025`<br>- Clave AES: `SHA-256(Key_String)` (32 bytes)<br>- IV AES: `SHA-256(IV_String)[:16]` (16 bytes primer bloque)<br>- Padding: Alineación a múltiplos de 16 bytes con `\0`. |
| **6** | **Cabecera Payload Interior** | 60 bytes. Magic `0x01020304`, payload **Tipo 0** (compresión ZLIB plana). Contiene tamaño descomprimido, tamaño acumulado y CRC32. |
| **7** | **Compresión ZLIB** | Bloques de hasta 65,536 bytes (64 KB) con compresión `Z_BEST_COMPRESSION` y suma de verificación CRC32. |

---

## 🛠️ Uso Avanzado directo desde Python

Si prefieres ejecutar el script de Python directamente:

```bash
# Usando el python del venv:
../bin/python3 f6600_tool.py decrypt config.bin salida.xml
../bin/python3 f6600_tool.py encrypt salida.xml config_enc.bin

# Ver ayuda:
../bin/python3 f6600_tool.py --help
```

---

## ❓ Preguntas Frecuentes y Solución de Problemas

### 1. ¿Cómo compruebo si el archivo generado es idéntico al original?
Si decriptas `config.bin` y lo vuelves a encriptar sin modificar el XML, el resultado es **100% idéntico bit por bit**:
```bash
./decrypt.sh config.bin test.xml
./encrypt.sh test.xml test.bin
cmp config.bin test.bin
# Si no devuelve salida, los archivos son idénticos byte por byte.
```

### 2. Error: "Permission denied" al ejecutar los scripts
Asegúrate de que tengan permisos de ejecución:
```bash
chmod +x decrypt.sh encrypt.sh f6600_tool.py
```

### 3. Error al restaurar en el router
- Verifica que al editar el archivo XML no hayas eliminado etiquetas de cierre (`</...>`) o introducido caracteres que invaliden la estructura XML.
- Guarda el archivo siempre en codificación `UTF-8` sin BOM.
