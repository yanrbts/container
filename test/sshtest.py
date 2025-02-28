import paramiko

def ssh_test(host, port, username, password, command):
    # 创建 SSH 客户端对象
    ssh = paramiko.SSHClient()
    
    # 自动添加主机的 SSH 密钥（首次连接时会提示你确认主机指纹）
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # 连接到 SSH 服务器
        print(f"Connecting to {host}:{port} as {username}...")
        ssh.connect(host, port=port, username=username, password=password)
        
        # 执行命令并获取结果
        print(f"Executing command: {command}")
        stdin, stdout, stderr = ssh.exec_command(command)
        
        # 输出命令结果
        print("Command Output:")
        print(stdout.read().decode())
        
        # 错误输出
        err = stderr.read().decode()
        if err:
            print("Error Output:")
            print(err)
    
    except Exception as e:
        print(f"Error: {e}")
    
    finally:
        # 关闭连接
        ssh.close()
        print("Connection closed.")

if __name__ == "__main__":
    host = "127.0.0.1"  # SSH 服务器地址
    port = 2222          # SSH 端口
    username = "yrb"     # 登录用户名
    password = "123"  # 登录密码
    command = "ls"  # 你想执行的命令
    
    # 调用函数进行 SSH 连接和测试
    ssh_test(host, port, username, password, command)
