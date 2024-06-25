import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import threading
import asyncio
import subprocess
import os
import signal

class ConfigGUI:
    def __init__(self, master):
        self.master = master
        master.title("탭클라우드잇 설치 윈도우")

        self.main_frame = ttk.Frame(master, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.create_config_entries()

        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.pack(pady=10)

        self.save_button = ttk.Button(self.button_frame, text="설정 저장", command=self.save_config)
        self.save_button.pack(side=tk.LEFT, padx=5)

        self.run_button = ttk.Button(self.button_frame, text="스크립트 실행", command=self.run_script)
        self.run_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(self.button_frame, text="실행 중단", command=self.stop_script, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.log_text = tk.Text(self.main_frame, wrap=tk.WORD, width=60, height=10)
        self.log_text.pack(pady=10)

        self.progress = ttk.Progressbar(self.main_frame, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.progress.pack(pady=10)

        self.save_log_button = ttk.Button(self.button_frame, text="로그 저장", command=self.save_log)
        self.save_log_button.pack(side=tk.LEFT, padx=5)

        self.script_running = False
        self.script_process = None

    def load_config_schema(self):
        try:
            with open('config_schema.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            messagebox.showerror("오류", "config_schema.json 파일을 찾을 수 없습니다.")
            return []
        except json.JSONDecodeError:
            messagebox.showerror("오류", "config_schema.json 파일의 형식이 잘못되었습니다.")
            return []

    def create_config_entries(self):
        self.entries = {}
        self.checkbuttons = {}
        configs = self.load_config_schema()

        for tab_name, tab_configs in configs:
            tab = ttk.Frame(self.notebook)
            self.notebook.add(tab, text=tab_name)

            for i, (key, label, default_value, is_boolean) in enumerate(tab_configs):
                ttk.Label(tab, text=label).grid(column=0, row=i, sticky=tk.W, pady=4)
                if is_boolean:
                    var = tk.BooleanVar(value=default_value.lower() == 'true')
                    checkbutton = ttk.Checkbutton(tab, variable=var)
                    checkbutton.grid(column=1, row=i, sticky=(tk.W, tk.E), pady=4)

                    text_var = tk.StringVar(value="ON" if var.get() else "OFF")
                    label = ttk.Label(tab, textvariable=text_var)
                    label.grid(column=2, row=i, sticky=tk.W, pady=2)

                    def update_text(var=var, text_var=text_var):
                        text_var.set("ON" if var.get() else "OFF")

                    var.trace("w", lambda *args, v=var, tv=text_var: update_text(v, tv))

                    self.checkbuttons[key] = checkbutton
                    self.entries[key] = var
                else:
                    self.entries[key] = ttk.Entry(tab)
                    self.entries[key].insert(0, default_value)
                    self.entries[key].grid(column=1, row=i, columnspan=2, sticky=(tk.W, tk.E), pady=2)

    def save_config(self):
        try:
            config = {}
            for key, entry in self.entries.items():
                if isinstance(entry, tk.BooleanVar):
                    config[key] = entry.get()
                else:
                    value = entry.get()
                    if value.isdigit():
                        config[key] = int(value)
                    else:
                        config[key] = value

            with open('config.tf', 'w') as f:
                for key, value in config.items():
                    if isinstance(value, bool):
                        f.write(f'{key} = {str(value).lower()}\n')
                    elif isinstance(value, int):
                        f.write(f'{key} = {value}\n')
                    else:
                        f.write(f'{key} = "{value}"\n')

            messagebox.showinfo("설정 저장", "설정이 성공적으로 저장되었습니다.")
        except IOError:
            messagebox.showerror("저장 오류", "설정 파일을 저장하는 중 오류가 발생했습니다.")
        except Exception as e:
            messagebox.showerror("오류", f"예기치 않은 오류가 발생했습니다: {str(e)}")

    def save_log(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            log_content = self.log_text.get("1.0", tk.END)
            try:
                with open(file_path, "w", encoding="utf-8") as file:
                    file.write(log_content)
                messagebox.showinfo("로그 저장", f"로그가 성공적으로 저장되었습니다:\n{file_path}")
            except IOError:
                messagebox.showerror("저장 오류", "로그 파일을 저장하는 중 오류가 발생했습니다.")

    def run_script(self):
        self.progress['value'] = 0
        self.master.update_idletasks()

        self.script_running = True
        self.run_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        threading.Thread(target=self.execute_script_async, daemon=True).start()

    def execute_script_async(self):
        asyncio.run(self.execute_script())

    async def execute_script(self):
        try:
            process = await asyncio.create_subprocess_exec(
                "python", "your_script.py",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                self.log_text.insert(tk.END, line.decode())
                self.log_text.see(tk.END)
                self.master.update_idletasks()

                # Update progress bar (you may need to adjust this based on your script's output)
                if line.startswith(b'Progress:'):
                    progress = int(line.split(b':')[1])
                    self.progress['value'] = progress
                    self.master.update_idletasks()

            await process.wait()
        except Exception as e:
            self.log_text.insert(tk.END, f"오류 발생: {str(e)}\n")
        finally:
            self.script_running = False
            self.run_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.script_process = None

            if self.progress['value'] == 100:
                messagebox.showinfo("실행 완료", "스크립트 실행이 완료되었습니다.")
            else:
                self.log_text.insert(tk.END, "스크립트 실행이 중단되었습니다.\n")

    def stop_script(self):
        if not self.script_running:
            return

        self.script_running = False
        if self.script_process:
            if os.name == 'nt':
                subprocess.call(['taskkill', '/F', '/T', '/PID', str(self.script_process.pid)])
            else:
                os.killpg(os.getpgid(self.script_process.pid), signal.SIGTERM)

        self.log_text.insert(tk.END, "스크립트 실행 중단 요청...\n")
        self.log_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    gui = ConfigGUI(root)
    root.mainloop()