# import os
# import paramiko
# import socket
# import threading
# import sys

# # 监听地址和端口
# HOST = "0.0.0.0"
# PORT = 2222

# # SSH 服务器密钥
# HOST_KEY = paramiko.RSAKey.generate(2048)

# # 用户名和密码（简单示例，建议使用更安全的方法）
# USER_CREDENTIALS = {
#     "user": "123"
# }

# # 创建新的 namespace 并隔离文件系统
# def setup_namespace():
#     pid = os.getpid()
#     new_root = f"/tmp/jail_{pid}"
#     old_root = f"{new_root}/old_root"

#     # 创建新的目录结构
#     os.makedirs(new_root, exist_ok=True)
#     os.makedirs(old_root, exist_ok=True)

#     # 创建新的 mount namespace
#     os.system(f"unshare -m")

#     # 挂载新的根目录
#     os.system(f"mount --bind {new_root} {new_root}")

#     # 切换根目录
#     os.system(f"pivot_root {new_root} {old_root}")

#     # 切换到新根
#     os.chdir("/")

#     # 卸载旧的根目录
#     os.system("umount -l /old_root")
#     os.rmdir("/old_root")

#     # 挂载独立的 /proc
#     os.system("mount -t proc proc /proc")

# # SSH 处理类
# class SSHHandler(paramiko.ServerInterface):
#     def __init__(self):
#         super().__init__()
#         self.event = threading.Event()

#     def check_auth_password(self, username, password):
#         if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
#             return paramiko.AUTH_SUCCESSFUL
#         return paramiko.AUTH_FAILED

#     def check_channel_request(self, kind, chanid):
#         if kind == "session":
#             return paramiko.OPEN_SUCCEEDED
#         return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

#     def check_channel_shell_request(self, channel):
#         self.event.set()
#         return True

# # 处理 SSH 客户端
# def handle_client(client):
#     transport = paramiko.Transport(client)
#     transport.add_server_key(HOST_KEY)
#     server = SSHHandler()
    
#     try:
#         transport.start_server(server=server)
#         channel = transport.accept(20)
#         if channel is None:
#             return

#         # 创建 shell
#         server.event.wait(10)
#         if not server.event.is_set():
#             return

#         # 在新 namespace 中运行 shell
#         pid = os.fork()
#         if pid == 0:
#             try:
#                 setup_namespace()

#                 # 获取 pseudo-terminal (PTY)
#                 os.dup2(channel.fileno(), sys.stdin.fileno())
#                 os.dup2(channel.fileno(), sys.stdout.fileno())
#                 os.dup2(channel.fileno(), sys.stderr.fileno())
#                 os.execvp("/bin/bash", ["/bin/bash"])
#             except Exception as e:
#                 print(f"Error in child process: {e}")
#                 sys.exit(1)
#         else:
#             os.waitpid(pid, 0)

#     except Exception as e:
#         print(f"Error: {e}")
#     finally:
#         transport.close()
#         client.close()

# # 启动 SSH 服务器
# def start_ssh_server():
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     server_socket.bind((HOST, PORT))
#     server_socket.listen(100)

#     print(f"SSH Server listening on {HOST}:{PORT}")

#     while True:
#         client, addr = server_socket.accept()
#         print(f"New connection from {addr}")
#         threading.Thread(target=handle_client, args=(client,)).start()

# if __name__ == "__main__":
#     start_ssh_server()


# import os
# import paramiko
# import socket
# import threading
# import sys
# import subprocess

# HOST = "0.0.0.0"
# PORT = 2222
# HOST_KEY = paramiko.RSAKey.generate(2048)

# USER_CREDENTIALS = {
#     "user": "123"
# }

# def setup_namespace():
#     pid = os.getpid()
#     new_root = f"/tmp/jail_{pid}"

#     # 创建新的 root 目录
#     os.makedirs(new_root, exist_ok=True)

#     # 复制基础系统文件
#     os.system(f"cp -r /bin /lib /lib64 /usr {new_root}/")

#     # 切换 root 并进入新环境
#     os.chroot(new_root)
#     os.chdir("/")

#     # 重新挂载 /proc
#     os.system("mount -t proc proc /proc")

# class SSHHandler(paramiko.ServerInterface):
#     def __init__(self):
#         super().__init__()
#         self.event = threading.Event()

#     def check_auth_password(self, username, password):
#         if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
#             return paramiko.AUTH_SUCCESSFUL
#         return paramiko.AUTH_FAILED

#     def check_channel_request(self, kind, chanid):
#         if kind == "session":
#             return paramiko.OPEN_SUCCEEDED
#         return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

#     def check_channel_shell_request(self, channel):
#         self.event.set()
#         return True

# def handle_client(client):
#     transport = paramiko.Transport(client)
#     transport.add_server_key(HOST_KEY)
#     server = SSHHandler()
    
#     try:
#         transport.start_server(server=server)
#         channel = transport.accept(20)
#         if channel is None:
#             return

#         # 绑定 PTY
#         channel.get_pty()

#         # 创建 shell
#         server.event.wait(10)
#         if not server.event.is_set():
#             return

#         # 在新 namespace 运行 shell
#         pid = os.fork()
#         if pid == 0:
#             try:
#                 setup_namespace()

#                 # 绑定 SSH 终端到子进程
#                 os.dup2(channel.fileno(), sys.stdin.fileno())
#                 os.dup2(channel.fileno(), sys.stdout.fileno())
#                 os.dup2(channel.fileno(), sys.stderr.fileno())

#                 # 启动交互式 shell
#                 os.execvp("/bin/bash", ["/bin/bash"])
#             except Exception as e:
#                 print(f"Error in child process: {e}")
#                 sys.exit(1)
#         else:
#             os.waitpid(pid, 0)

#     except Exception as e:
#         print(f"Error: {e}")
#     finally:
#         transport.close()
#         client.close()

# def start_ssh_server():
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     server_socket.bind((HOST, PORT))
#     server_socket.listen(100)

#     print(f"SSH Server listening on {HOST}:{PORT}")

#     while True:
#         client, addr = server_socket.accept()
#         print(f"New connection from {addr}")
#         threading.Thread(target=handle_client, args=(client,)).start()

# if __name__ == "__main__":
#     start_ssh_server()


import paramiko
import socket
import threading
import os
import pty
import sys
import select

# 启用 Paramiko 日志
paramiko.util.log_to_file("paramiko.log", level=paramiko.common.DEBUG)

HOST = "0.0.0.0"
PORT = 2222
HOST_KEY = paramiko.RSAKey.generate(2048)
USER_CREDENTIALS = {
    "user": "123"
}

class SSHHandler(paramiko.ServerInterface):
    def __init__(self):
        super().__init__()
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        print(f"check_auth_password: {username}")
        if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
            print("Authentication successful")
            return paramiko.AUTH_SUCCESSFUL
        print("Authentication failed")
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        print(f"check_channel_request: kind={kind}")
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        print("check_channel_shell_request: accepted")
        self.event.set()  # 确保 shell 事件触发
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        print(f"PTY request: term={term}, width={width}, height={height}")
        self.event.set()  # 确保 PTY 事件触发
        return True

def handle_client(client):
    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)
    server = SSHHandler()

    try:
        print("Starting SSH server...")
        transport.start_server(server=server)

        print("Accepting channel...")
        channel = transport.accept(60)
        if channel is None:
            print("Channel is None, closing connection")
            return

        print("Checking if channel is active...")
        if not channel.active:
            print("Channel is not active, closing connection")
            return

        print("Waiting for PTY request...")
        server.event.wait(10)  # 等待 `PTY` 事件触发
        if not server.event.is_set():
            print("PTY request was not granted, closing connection")
            return

        print("Invoking shell...")
        try:
            print("Checking if channel is active before invoking shell...")
            if not channel.active:
                print("Channel closed before invoking shell, aborting")
                return
            channel.get_pty()
            channel.invoke_shell()
            print("Shell invoked successfully!")
        except Exception as e:
            print(f"Failed to invoke shell: {e}")
            return

        print("Starting shell...")

        pid, fd = pty.fork()
        if pid == 0:  # 子进程
            os.setsid()
            os.dup2(fd, 0)  # stdin
            os.dup2(fd, 1)  # stdout
            os.dup2(fd, 2)  # stderr
            print("Starting /bin/bash...")
            try:
                os.setuid(os.getpwnam("nobody").pw_uid)
                os.execv("/bin/bash", ["/bin/bash"])
            except Exception as e:
                print(f"Failed to execute bash: {e}")
                sys.exit(1)
        else:  # 父进程
            try:
                while True:
                    r, _, _ = select.select([fd, channel], [], [])
                    if fd in r:
                        data = os.read(fd, 1024)
                        if not data:
                            print("No data from child process, breaking loop")
                            break
                        channel.send(data)
                    if channel in r:
                        data = channel.recv(1024)
                        if not data:
                            print("No data from channel, breaking loop")
                            break
                        os.write(fd, data)
            except Exception as e:
                print(f"Error in parent process: {e}")
            finally:
                channel.close()
                print("Channel closed")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        print("Closing connection")
        transport.close()
        client.close()

def start_ssh_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(100)

    print(f"SSH Server listening on {HOST}:{PORT}")

    while True:
        client, addr = server_socket.accept()
        print(f"New connection from {addr}")
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == "__main__":
    start_ssh_server()


