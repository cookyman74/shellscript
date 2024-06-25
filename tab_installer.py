import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import threading
import subprocess
import psutil

class ConfigGUI:
    def __init__(self, master):
        self.master = master
        master.title("탭클라우드잇 설치 윈도우")

        # 메인 프레임
        self.main_frame = ttk.Frame(master, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # 설정 항목들을 포함할 노트북 (탭) 생성
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 설정 항목들
        self.create_config_entries()

        # 버튼 프레임
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.pack(pady=10)

        # 저장 버튼
        self.save_button = ttk.Button(self.button_frame, text="설정 저장", command=self.save_config)
        self.save_button.pack(side=tk.LEFT, padx=5)

        # 실행 버튼
        self.run_button = ttk.Button(self.button_frame, text="스크립트 실행", command=self.run_script)
        self.run_button.pack(side=tk.LEFT, padx=5)

        # 중단 버튼
        self.stop_button = ttk.Button(self.button_frame, text="실행 중단", command=self.stop_script, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # 로그 출력 영역
        self.log_text = tk.Text(self.main_frame, wrap=tk.WORD, width=60, height=10)
        self.log_text.pack(pady=10)

        # 프로그레스 바
        self.progress = ttk.Progressbar(self.main_frame, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.progress.pack(pady=10)

        # 로그 저장 버튼
        self.save_log_button = ttk.Button(self.button_frame, text="로그 저장", command=self.save_log)
        self.save_log_button.pack(side=tk.LEFT, padx=5)

        # 스크립트 실행 상태 및 프로세스 추적
        self.script_running = False
        self.script_process = None
        self.script_stopped = False

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
        self.script_stopped = False
        self.run_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        threading.Thread(target=self.execute_script, daemon=True).start()

    def execute_script(self):
        try:
            self.script_process = subprocess.Popen(
                ["./install_test.sh"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            for line in self.script_process.stdout:
                if not self.script_running:
                    break

                line = line.strip()
                self.master.after(0, self.update_gui, line)

            self.script_process.wait()

        except Exception as e:
            self.master.after(0, self.update_gui, f"오류 발생: {str(e)}")
        finally:
            if self.script_running:
                self.script_running = False
                self.master.after(0, self.update_gui_final)
            elif not self.script_stopped:
                # 스크립트가 정상적으로 완료된 경우
                self.master.after(0, self.update_gui, "스크립트 실행이 완료되었습니다.")
                self.master.after(10, self.update_gui_final)

    def update_gui(self, line):
        self.log_text.insert(tk.END, line + "\n")
        self.log_text.see(tk.END)

        if line.startswith("Progress:"):
            try:
                progress = int(line.split(":")[1])
                self.progress['value'] = progress
            except (IndexError, ValueError):
                pass  # 잘못된 형식의 Progress 라인 무시

        self.master.update_idletasks()

    def update_gui_final(self):
        self.run_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

        if self.progress['value'] == 100 and not self.script_stopped:
            messagebox.showinfo("실행 완료", "스크립트 실행이 완료되었습니다.")
        elif self.script_stopped:
            # 이미 메시지가 로그에 추가되었으므로 여기서는 추가하지 않습니다.
            pass

        self.script_process = None
        self.script_stopped = False  # 상태 초기화

    def stop_script(self):
        if not self.script_running or not self.script_process:
            return

        self.script_running = False
        self.script_stopped = True

        try:
            parent = psutil.Process(self.script_process.pid)
            children = parent.children(recursive=True)

            for child in children:
                child.terminate()

            parent.terminate()

            gone, still_alive = psutil.wait_procs(children + [parent], timeout=3)

            for p in still_alive:
                p.kill()

        except psutil.NoSuchProcess:
            pass

        # GUI 업데이트를 위해 update_gui 메서드 직접 호출
        self.master.after(0, self.update_gui, "스크립트 실행이 중단되었습니다.")
        self.master.after(10, self.update_gui_final)

if __name__ == "__main__":
    root = tk.Tk()
    gui = ConfigGUI(root)
    root.mainloop()