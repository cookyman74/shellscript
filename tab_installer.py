import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import threading
import time
import random
import subprocess
import os
import signal

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

    def save_log(self):
        # 파일 저장 대화상자 열기
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            # 로그 텍스트 가져오기
            log_content = self.log_text.get("1.0", tk.END)

            # 파일에 로그 내용 쓰기
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(log_content)

            messagebox.showinfo("로그 저장", f"로그가 성공적으로 저장되었습니다:\n{file_path}")

    def create_config_entries(self):
        self.entries = {}
        self.checkbuttons = {}
        configs = [
            ("일반 설정", [
                ("nodes_ssh_port", "SSH 포트", "22", False),
                ("nodes_ssh_user", "SSH 사용자", "openstack", False),
                ("nodes_ssh_password", "SSH 비밀번호", "qwe1212!Q", False),
                ("enable_upgrade_process", "업그레이드 프로세스 활성화", "false", True),
                ("data_mount_directory", "데이터 마운트 디렉토리", "/data", False),
                ("create_data_directory_if_not_mounted", "마운트되지 않은 경우 데이터 디렉토리 생성", "false", True),
                ("enable_ssl", "SSL 활성화", "true", True),
            ]),
            ("서버 설정", [
                ("mariadb_install_target_ip_address", "MariaDB 설치 대상 IP 주소", "192.168.122.102", False),
                ("was_server_ip_address", "WAS 서버 IP 주소", "192.168.122.101", False),
                ("key_store_password", "키 스토어 비밀번호", "qwe1212!Q", False),
                ("netbox_install_target_ip_address", "NetBox 설치 대상 IP 주소", "192.168.122.101", False),
                ("rabbitmq_install_target_ip_address", "RabbitMQ 설치 대상 IP 주소", "192.168.122.101", False),
                ("batch_server_ip_address", "Batch 서버 IP 주소", "192.168.122.103", False),
                ("influxdb_install_target_ip_address", "InfluxDB 설치 대상 IP 주소", "192.168.122.103", False),
            ]),
            ("TabCloudit 설정", [
                ("tabcloudit_enable_openstack", "OpenStack 활성화", "true", True),
                ("tabcloudit_enable_vmware", "VMware 활성화", "false", True),
                ("tabcloudit_enable_openshift", "OpenShift 활성화", "true", True),
                ("openstack_api_ip_address", "OpenStack API IP 주소", "192.168.130.130", False),
                ("minio_ip_address", "MinIO IP 주소", "210.207.104.213", False),
                ("kapacitor_ip_address", "Kapacitor IP 주소", "192.168.130.8", False),
                ("sms_ip_address", "SMS IP 주소", "10.232.181.152", False),
            ]),
            ("OpenShift 설정", [
                ("openshift_domain", "OpenShift 도메인", "ocp4.inno.com", False),
                ("openshift_master_ip_address", "OpenShift 마스터 IP 주소", "192.168.150.246", False),
                ("openshift_worker_ip_address", "OpenShift 워커 IP 주소", "192.168.150.246", False),
            ]),
        ]

        for tab_name, tab_configs in configs:
            tab = ttk.Frame(self.notebook)
            self.notebook.add(tab, text=tab_name)

            for i, (key, label, default_value, is_boolean) in enumerate(tab_configs):
                ttk.Label(tab, text=label).grid(column=0, row=i, sticky=tk.W, pady=4)
                if is_boolean:
                    var = tk.BooleanVar(value=default_value.lower() == 'true')
                    checkbutton = ttk.Checkbutton(tab, variable=var)
                    checkbutton.grid(column=1, row=i, sticky=(tk.W, tk.E), pady=4)

                    # 텍스트 라벨 추가
                    text_var = tk.StringVar(value="ON" if var.get() else "OFF")
                    label = ttk.Label(tab, textvariable=text_var)
                    label.grid(column=2, row=i, sticky=tk.W, pady=2)

                    # 체크박스 상태 변경 시 텍스트 업데이트 함수
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

    def run_script(self):
        # 프로그레스 바 초기화
        self.progress['value'] = 0
        self.master.update_idletasks()

        # 스크립트 실행 상태 업데이트
        self.script_running = True
        self.run_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        # 별도의 스레드에서 스크립트 실행
        thread = threading.Thread(target=self.execute_script)
        thread.start()

    def execute_script(self):
        try:
            # 실제 스크립트 실행 (여기서는 예시로 'echo' 명령어 사용)
            self.script_process = subprocess.Popen(["echo", "스크립트 실행 중..."],
                                                   stdout=subprocess.PIPE,
                                                   stderr=subprocess.PIPE,
                                                   text=True)

            # 스크립트 실행 시뮬레이션
            for i in range(100):
                if not self.script_running:
                    break
                time.sleep(0.1)
                progress = min(self.progress['value'] + random.randint(1, 5), 100)
                self.progress['value'] = progress
                self.master.update_idletasks()
                self.log_text.insert(tk.END, f"진행 중... {progress}%\n")
                self.log_text.see(tk.END)

            # 스크립트 실행 결과 처리
            stdout, stderr = self.script_process.communicate()
            if stdout:
                self.log_text.insert(tk.END, f"출력: {stdout}\n")
            if stderr:
                self.log_text.insert(tk.END, f"오류: {stderr}\n")

        except Exception as e:
            self.log_text.insert(tk.END, f"오류 발생: {str(e)}\n")
        finally:
            # 스크립트 실행 상태 업데이트
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
            # Windows의 경우
            if os.name == 'nt':
                subprocess.call(['taskkill', '/F', '/T', '/PID', str(self.script_process.pid)])
            # Unix/Linux의 경우
            else:
                os.killpg(os.getpgid(self.script_process.pid), signal.SIGTERM)

        self.log_text.insert(tk.END, "스크립트 실행 중단 요청...\n")
        self.log_text.see(tk.END)

root = tk.Tk()
gui = ConfigGUI(root)
root.mainloop()