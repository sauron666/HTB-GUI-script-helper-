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

    def _style_widget(self, widget):
        widget.configure(bg=self.THEME["bg"], fg=self.THEME["fg"], insertbackground=self.THEME["fg"], font=self.THEME["font"])

    def _styled_label(self, parent, text):
        label = tk.Label(parent, text=text, bg=self.THEME["bg"], fg=self.THEME["fg"], font=("Consolas", 11, "bold"))
        label.pack(pady=2)
        return label

    def _styled_entry(self, parent, default=""):
        entry = tk.Entry(parent, bg=self.THEME["input_bg"], fg=self.THEME["input_fg"], insertbackground=self.THEME["fg"], font=self.THEME["font"])
        entry.insert(0, default)
        entry.pack(pady=2, fill='x')
        return entry

    def _styled_button(self, parent, text, cmd):
        btn = tk.Button(parent, text=text, command=cmd, bg=self.THEME["button_bg"], fg=self.THEME["button_fg"], font=("Consolas", 10))
        btn.pack(pady=2)
        return btn

    def _styled_text(self, parent, height=15):
        txt = scrolledtext.ScrolledText(parent, height=height, bg=self.THEME["text_bg"], fg=self.THEME["text_fg"], insertbackground=self.THEME["fg"], font=self.THEME["font"])
        txt.pack(pady=2, fill='both', expand=True)
        return txt

    # Всички init_XXX_tab() могат да използват горните стил функции за темизиране

if __name__ == "__main__":
    root = tk.Tk()
    app = HTBToolkitApp(root)
    root.mainloop()

# ---- Next File ----
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

class HTBToolkitApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HackTheBox Toolkit")
        self.root.geometry("1000x800")

        self.tab_control = ttk.Notebook(root)

        self.shell_tab = ttk.Frame(self.tab_control)
        self.reverse_tab = ttk.Frame(self.tab_control)
        self.exploit_tab = ttk.Frame(self.tab_control)
        self.file_tab = ttk.Frame(self.tab_control)
        self.brute_tab = ttk.Frame(self.tab_control)
        self.portscan_tab = ttk.Frame(self.tab_control)
        self.wordlist_tab = ttk.Frame(self.tab_control)
        self.export_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.shell_tab, text='Shell Tools')
        self.tab_control.add(self.reverse_tab, text='Reverse Shells')
        self.tab_control.add(self.exploit_tab, text='Exploits')
        self.tab_control.add(self.file_tab, text='File Ops')
        self.tab_control.add(self.brute_tab, text='BruteForce')
        self.tab_control.add(self.portscan_tab, text='Port Scanner')
        self.tab_control.add(self.wordlist_tab, text='Wordlists')
        self.tab_control.add(self.export_tab, text='Export/Report')

        self.tab_control.pack(expand=1, fill='both')

        self.init_shell_tab()
        self.init_reverse_tab()
        self.init_exploit_tab()
        self.init_file_tab()
        self.init_brute_tab()
        self.init_portscan_tab()
        self.init_wordlist_tab()
        self.init_export_tab()

    def init_export_tab(self):
        tk.Label(self.export_tab, text="Export Toolkit Results:", font=('Arial', 12, 'bold')).pack(pady=5)

        self.export_text = scrolledtext.ScrolledText(self.export_tab, height=30)
        self.export_text.pack(pady=5)

        tk.Button(self.export_tab, text="Load Text File", command=self.load_export_file).pack(pady=2)
        tk.Button(self.export_tab, text="Save to TXT", command=self.save_export_txt).pack(pady=2)
        tk.Button(self.export_tab, text="Save to CSV", command=self.save_export_csv).pack(pady=2)

    def load_export_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    self.export_text.delete(1.0, tk.END)
                    self.export_text.insert(tk.END, f.read())
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def save_export_txt(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.export_text.get(1.0, tk.END))
                messagebox.showinfo("Saved", "Saved to TXT successfully!")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def save_export_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file_path:
            try:
                lines = self.export_text.get(1.0, tk.END).strip().splitlines()
                with open(file_path, 'w', encoding='utf-8') as f:
                    for line in lines:
                        f.write(line.replace("\t", ",") + "\n")
                messagebox.showinfo("Saved", "Saved to CSV successfully!")
            except Exception as e:
                messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = HTBToolkitApp(root)
    root.mainloop()

# ---- Next File ----
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

class HTBToolkitApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HackTheBox Toolkit")
        self.root.geometry("1000x750")

        self.tab_control = ttk.Notebook(root)

        self.shell_tab = ttk.Frame(self.tab_control)
        self.reverse_tab = ttk.Frame(self.tab_control)
        self.exploit_tab = ttk.Frame(self.tab_control)
        self.file_tab = ttk.Frame(self.tab_control)
        self.brute_tab = ttk.Frame(self.tab_control)
        self.portscan_tab = ttk.Frame(self.tab_control)
        self.wordlist_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.shell_tab, text='Shell Tools')
        self.tab_control.add(self.reverse_tab, text='Reverse Shells')
        self.tab_control.add(self.exploit_tab, text='Exploits')
        self.tab_control.add(self.file_tab, text='File Ops')
        self.tab_control.add(self.brute_tab, text='BruteForce')
        self.tab_control.add(self.portscan_tab, text='Port Scanner')
        self.tab_control.add(self.wordlist_tab, text='Wordlists')

        self.tab_control.pack(expand=1, fill='both')

        self.init_shell_tab()
        self.init_reverse_tab()
        self.init_exploit_tab()
        self.init_file_tab()
        self.init_brute_tab()
        self.init_portscan_tab()
        self.init_wordlist_tab()

    # ... (предишните методи са същите)

    def init_wordlist_tab(self):
        tk.Label(self.wordlist_tab, text="Preview Wordlist File:").pack()

        self.wordlist_text = scrolledtext.ScrolledText(self.wordlist_tab, height=30)
        self.wordlist_text.pack(pady=5)

        tk.Button(self.wordlist_tab, text="Load Wordlist", command=self.load_and_preview_wordlist).pack()

    def load_and_preview_wordlist(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = [line.strip() for line in f if line.strip()]
                self.wordlist_text.delete(1.0, tk.END)
                for line in lines[:500]:
                    self.wordlist_text.insert(tk.END, line + "\n")
                if len(lines) > 500:
                    self.wordlist_text.insert(tk.END, f"... ({len(lines)} lines total)\n")
            except Exception as e:
                messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = HTBToolkitApp(root)
    root.mainloop()


# ---- Next File ----
