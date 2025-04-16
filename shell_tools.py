
import os
import subprocess
import platform

def run_command(cmd):
    """Изпълнява системна команда и връща stdout + stderr."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout + result.stderr
    except Exception as e:
        return f"[!] Грешка при изпълнение на командата: {e}"

def get_system_info():
    """Събира основна информация за системата."""
    info = {
        "OS": platform.system(),
        "OS Version": platform.version(),
        "Architecture": platform.machine(),
        "User": os.getenv("USER") or os.getenv("USERNAME"),
        "Hostname": platform.node()
    }
    return info

def list_directory(path="."):
    """Листва съдържанието на директория."""
    try:
        return os.listdir(path)
    except Exception as e:
        return [f"[!] Грешка: {e}"]

def current_user():
    """Връща текущия потребител чрез whoami."""
    return run_command("whoami")

def network_info():
    """Връща информация за мрежата (IP, интерфейси)."""
    if platform.system() == "Windows":
        return run_command("ipconfig")
    else:
        return run_command("ifconfig || ip a")

def running_processes():
    """Списък на текущо стартирани процеси."""
    return run_command("ps aux" if platform.system() != "Windows" else "tasklist")

def file_permissions(path):
    """Връща права на файл."""
    try:
        return oct(os.stat(path).st_mode)[-3:]
    except Exception as e:
        return f"[!] Грешка: {e}"
