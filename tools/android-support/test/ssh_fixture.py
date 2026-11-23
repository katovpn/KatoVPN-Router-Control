"""Loopback-only SSH fixture; depends on the local Paramiko test dependency."""

import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import paramiko


class PasswordServer(paramiko.ServerInterface):
    def __init__(self):
        self.password_requests = 0
        self.scripts = []
        self.workers = []
        self.writes = 0

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self.password_requests += 1
        if (username, password) == ("root", "in-memory-fixture"):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        # Match Dropbear's bounded command field; the program body can use stdin.
        if len(command) > 9000:
            return False
        worker = threading.Thread(target=self.exec_request, args=(channel, command), daemon=True)
        self.workers.append(worker)
        worker.start()
        return True

    def exec_request(self, channel, command):
        channel.settimeout(5)
        try:
            payload = bytearray()
            while chunk := channel.recv(16384):
                payload.extend(chunk)
                if len(payload) > 64000:
                    return
            with tempfile.TemporaryDirectory(prefix="kato-ssh-fixture-") as temp:
                root = Path(temp)
                for rel in ("etc/dropbear", "etc/crontabs", "etc/init.d", "etc/rc.d", "tmp", "bin"):
                    (root / rel).mkdir(parents=True)
                (root / "etc/init.d/cron").write_bytes(b"#!/bin/sh\nexit 0\n")
                (root / "etc/rc.d/S99cron").touch()
                (root / "bin/id").write_bytes(b"#!/bin/sh\nprintf '0\\n'\n")
                subprocess.run(["sh", "-c", "chmod +x etc/init.d/cron bin/id"], cwd=temp, check=True, timeout=4)
                (root / "ssh_exec.sh").write_bytes(b'PATH="$PWD/bin:$PATH"; export PATH\n' + command + b"\n")
                result = subprocess.run(["sh", "ssh_exec.sh"], cwd=temp, input=payload, capture_output=True, timeout=4)
                self.writes += sum((root / name).exists() for name in ("authorized_keys", "crontab", "session.sh"))
            if result.stdout:
                self.scripts.append(result.stdout.decode("ascii").strip())
                channel.sendall(result.stdout)
            channel.send_exit_status(result.returncode)
        except (socket.timeout, OSError):
            pass
        finally:
            channel.close()


def main():
    listeners = [socket.socket(), socket.socket()]
    servers = [PasswordServer(), PasswordServer()]
    keys = [paramiko.RSAKey.generate(2048), paramiko.RSAKey.generate(2048)]
    for listener in listeners:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(10)
    print(*(listener.getsockname()[1] for listener in listeners), flush=True)
    for index in (0, 1, 0):
        conn, _ = listeners[index].accept()
        with paramiko.Transport(conn) as transport:
            transport.add_server_key(keys[index])
            ready = threading.Event()
            transport.start_server(event=ready, server=servers[index])
            ready.wait(5)
            limit = time.monotonic() + 5
            while transport.is_active() and time.monotonic() < limit:
                time.sleep(0.02)
    for server in servers:
        for worker in server.workers:
            worker.join(7)
    print("auth:" + ",".join(str(server.password_requests) for server in servers)
          + " scripts:" + ",".join(servers[0].scripts) + " writes:" + str(servers[0].writes), flush=True)


if __name__ == "__main__":
    main()
