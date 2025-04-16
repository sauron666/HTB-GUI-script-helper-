
import os
import base64

def read_file(path):
    """Чете съдържанието на файл."""
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception as e:
        return f"[!] Грешка при четене: {e}"

def write_file(path, content):
    """Записва съдържание във файл."""
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        return "[+] Записано успешно."
    except Exception as e:
        return f"[!] Грешка при запис: {e}"

def delete_file(path):
    """Изтрива файл."""
    try:
        os.remove(path)
        return "[+] Файлът е изтрит."
    except Exception as e:
        return f"[!] Грешка при изтриване: {e}"

def change_permissions(path, mode):
    """Променя правата на файл (пример: 755, 644)."""
    try:
        os.chmod(path, int(mode, 8))
        return "[+] Правата са променени."
    except Exception as e:
        return f"[!] Грешка при chmod: {e}"

def generate_base64_payload(path):
    """Генерира base64 код за вмъкване/качване на файл."""
    try:
        with open(path, 'rb') as f:
            encoded = base64.b64encode(f.read()).decode('utf-8')
        return encoded
    except Exception as e:
        return f"[!] Грешка при генериране на base64: {e}"

def decode_base64_to_file(encoded_str, output_path):
    """Записва base64 payload като реален файл."""
    try:
        with open(output_path, 'wb') as f:
            f.write(base64.b64decode(encoded_str))
        return "[+] Base64 payload записан успешно като файл."
    except Exception as e:
        return f"[!] Грешка при декодиране: {e}"
