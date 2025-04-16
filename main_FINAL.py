
import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext, filedialog
import socket
import threading
import os

from reverse_shells import get_reverse_shells
from shell_tools import get_system_info, run_command, list_directory
from file_ops import read_file, write_file, delete_file
from exploit_templates import get_lfi_templates, get_cmd_injection_templates
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
        self.root.title("HackTheBox Toolkit")
        self.root.geometry("1000x800")
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

        self.shell_tab = self._create_tab("Shell Tools")
        self.reverse_tab = self._create_tab("Reverse Shells")
        self.exploit_tab = self._create_tab("Exploits")
        self.file_tab = self._create_tab("File Ops")
        self.brute_tab = self._create_tab("BruteForce")
        self.portscan_tab = self._create_tab("Port Scanner")
        self.wordlist_tab = self._create_tab("Wordlists")
        self.export_tab = self._create_tab("Export/Report")

        self.init_shell_tab()
        self.init_reverse_tab()
        self.init_exploit_tab()
        self.init_file_tab()
        self.init_brute_tab()
        self.init_portscan_tab()
        self.init_wordlist_tab()
        self.init_export_tab()

    def change_theme(self, name):
        self.current_theme_name = name
        self.THEME = THEMES[name]
        self.root.configure(bg=self.THEME["bg"])
        messagebox.showinfo("Theme Switched", f"Switched to {name}! Restart app to reapply.")

    def _create_tab(self, name):
        tab = ttk.Frame(self.tab_control)
        self.tab_control.add(tab, text=name)
        return tab

    def init_shell_tab(self):
        self._styled_label(self.shell_tab, "System Info")
        info = get_system_info()
        output = self._styled_text(self.shell_tab, height=8)
        output.insert(tk.END, "\n".join(f"{k}: {v}" for k, v in info.items()))

        self._styled_label(self.shell_tab, "Command")
        self.cmd_entry = self._styled_entry(self.shell_tab)
        self.cmd_output = self._styled_text(self.shell_tab)
        self._styled_button(self.shell_tab, "Run", self.run_shell_command)

    def run_shell_command(self):
        cmd = self.cmd_entry.get()
        result = run_command(cmd)
        self.cmd_output.delete(1.0, tk.END)
        self.cmd_output.insert(tk.END, result)

    def init_reverse_tab(self):
        self._styled_label(self.reverse_tab, "Attacker IP")
        self.ip_entry = self._styled_entry(self.reverse_tab, "10.10.14.23")

        self._styled_label(self.reverse_tab, "Port")
        self.port_entry = self._styled_entry(self.reverse_tab, "9001")

        self._styled_button(self.reverse_tab, "Generate", self.show_reverse_shells)
        self.shells_box = self._styled_text(self.reverse_tab, height=20)

    def show_reverse_shells(self):
        ip = self.ip_entry.get()
        port = self.port_entry.get()
        shells = get_reverse_shells(ip, port)
        self.shells_box.delete(1.0, tk.END)
        for name, cmd in shells.items():
            self.shells_box.insert(tk.END, f"[{name}]\n{cmd}\n\n")

    def init_exploit_tab(self):
        self._styled_label(self.exploit_tab, "Target URL")
        self.target_entry = self._styled_entry(self.exploit_tab, "http://example.com/page.php")
        self._styled_button(self.exploit_tab, "Show Payloads", self.show_exploits)
        self.exploit_output = self._styled_text(self.exploit_tab, height=20)

    def show_exploits(self):
        url = self.target_entry.get()
        payloads = get_lfi_templates(url) + get_cmd_injection_templates(url)
        self.exploit_output.delete(1.0, tk.END)
        for p in payloads:
            self.exploit_output.insert(tk.END, p + "\n")

    def init_file_tab(self):
        self._styled_label(self.file_tab, "File Path")
        self.file_entry = self._styled_entry(self.file_tab)
        self._styled_button(self.file_tab, "Read", self.read_file)
        self._styled_button(self.file_tab, "Delete", self.delete_file)
        self.file_text = self._styled_text(self.file_tab, height=20)

    def read_file(self):
        path = self.file_entry.get()
        content = read_file(path)
        self.file_text.delete(1.0, tk.END)
        self.file_text.insert(tk.END, content)

    def delete_file(self):
        path = self.file_entry.get()
        result = delete_file(path)
        messagebox.showinfo("Result", result)

    def init_brute_tab(self):
        self._styled_label(self.brute_tab, "Target IP")
        self.brute_ip = self._styled_entry(self.brute_tab)

        self._styled_label(self.brute_tab, "Port")
        self.brute_port = self._styled_entry(self.brute_tab, "22")

        self._styled_label(self.brute_tab, "Protocol")
        self.proto_combo = ttk.Combobox(self.brute_tab, values=["SSH", "FTP"], state="readonly")
        self.proto_combo.current(0)
        self.proto_combo.pack()

        self._styled_button(self.brute_tab, "Load Userlist", self.load_userlist)
        self._styled_button(self.brute_tab, "Load Passlist", self.load_passlist)
        self._styled_button(self.brute_tab, "Start BruteForce", self.run_brute)

        self.brute_output = self._styled_text(self.brute_tab)
        self.userlist, self.passlist = [], []

    def load_userlist(self):
        path = filedialog.askopenfilename()
        if path:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                self.userlist = [l.strip() for l in f if l.strip()]
            messagebox.showinfo("Loaded", f"{len(self.userlist)} users")

    def load_passlist(self):
        path = filedialog.askopenfilename()
        if path:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                self.passlist = [l.strip() for l in f if l.strip()]
            messagebox.showinfo("Loaded", f"{len(self.passlist)} passwords")

    def run_brute(self):
        ip, port = self.brute_ip.get(), int(self.brute_port.get())
        proto = self.proto_combo.get()
        self.brute_output.delete(1.0, tk.END)
        if not self.userlist or not self.passlist:
            self.brute_output.insert(tk.END, "[!] Load wordlists first\n")
            return
        result = ssh_bruteforce(ip, port, self.userlist, self.passlist) if proto == "SSH" else ftp_bruteforce(ip, self.userlist, self.passlist)
        if isinstance(result, list):
            for u, p in result:
                self.brute_output.insert(tk.END, f"[+] {u}:{p}\n")
        else:
            self.brute_output.insert(tk.END, str(result) + "\n")

    def init_portscan_tab(self):
        self._styled_label(self.portscan_tab, "Target IP")
        self.scan_ip = self._styled_entry(self.portscan_tab)

        self._styled_label(self.portscan_tab, "Port Range (e.g. 20-1000)")
        self.scan_ports = self._styled_entry(self.portscan_tab, "1-1024")

        self._styled_button(self.portscan_tab, "Start Scan", self.start_scan)
        self.portscan_output = self._styled_text(self.portscan_tab)

    def start_scan(self):
        ip = self.scan_ip.get()
        try:
            start, end = map(int, self.scan_ports.get().split("-"))
        except:
            messagebox.showerror("Invalid Range", "Enter as start-end")
            return
        self.portscan_output.delete(1.0, tk.END)
        def scan():
            for port in range(start, end + 1):
                try:
                    sock = socket.socket()
                    sock.settimeout(0.5)
                    if sock.connect_ex((ip, port)) == 0:
                        self.portscan_output.insert(tk.END, f"[+] Port {port} open\n")
                    sock.close()
                except:
                    pass
        threading.Thread(target=scan).start()

    def init_wordlist_tab(self):
        self._styled_label(self.wordlist_tab, "Preview Wordlist")
        self.wordlist_text = self._styled_text(self.wordlist_tab)
        self._styled_button(self.wordlist_tab, "Load Wordlist", self.load_and_preview_wordlist)

    def load_and_preview_wordlist(self):
        path = filedialog.askopenfilename()
        if path:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [l.strip() for l in f if l.strip()]
            self.wordlist_text.delete(1.0, tk.END)
            for line in lines[:500]:
                self.wordlist_text.insert(tk.END, line + "\n")

    def init_export_tab(self):
        self._styled_label(self.export_tab, "Export Toolkit Results")
        self.export_text = self._styled_text(self.export_tab, height=25)
        self._styled_button(self.export_tab, "Load Text File", self.load_export_file)
        self._styled_button(self.export_tab, "Save to TXT", self.save_export_txt)
        self._styled_button(self.export_tab, "Save to CSV", self.save_export_csv)

    def load_export_file(self):
        path = filedialog.askopenfilename()
        if path:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                self.export_text.delete(1.0, tk.END)
                self.export_text.insert(tk.END, f.read())

    def save_export_txt(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self.export_text.get(1.0, tk.END))

    def save_export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv")
        if path:
            lines = self.export_text.get(1.0, tk.END).splitlines()
            with open(path, 'w', encoding='utf-8') as f:
                for line in lines:
                    f.write(line.replace("\t", ",") + "\n")

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

if __name__ == "__main__":
    root = tk.Tk()
    app = HTBToolkitApp(root)
    root.mainloop()
