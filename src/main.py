import platform
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import random
import threading
import queue
import time
import json
import os
import uuid
import bcrypt
from collections import deque
import datetime
import base64
import requests
import logging
logging.basicConfig(level=logging.DEBUG)
from dotenv import load_dotenv
load_dotenv()  # 优先加载 .env 文件
import sys
import os
from shutil import which
import logging
from pathlib import Path

env_path = Path(__file__).resolve().parent / ".env"  # 确保从执行目录查找.env
load_dotenv(dotenv_path=env_path) 

# ------------------------- 用户管理系统 -------------------------
class UserManager:
    def __init__(self):
        self.access_token = os.getenv("GITHUB_TOKEN")
        self.repo_owner = os.getenv("REPO_OWNER")
        self.repo_name = os.getenv("REPO_NAME")
        self.file_path = os.getenv("FILE_PATH")
        self.users = []
        self.lock_duration = 300  # 5分钟锁定
        self.max_attempts = 5
        self._force_load_users()  # 初始化强制加载

    def _force_load_users(self):
        """强制从GitHub加载最新数据"""
        retry = 0
        while retry < 3:
            try:
                content = self._github_api_get_file()
                if isinstance(content, list):
                    self.users = content
                    # 确保数据结构完整性
                    for user in self.users:
                        user.setdefault('devices', [])
                    return
                retry += 1
                time.sleep(1)
            except Exception as e:
                logging.error(f"用户数据加载失败({retry+1}/3): {str(e)}")
                time.sleep(2)
        raise RuntimeError("无法加载用户数据，请检查网络连接")
    
    def get_user(self, username):
        """获取最新用户数据"""
        self._force_load_users()
        return next((u for u in self.users if u['username'] == username), None)
    
    @staticmethod
    def hash_password(password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    @staticmethod
    def check_password(password, hashed):
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def load_users(self):
        try:
            content = self._github_api_get_file()
            if content is not None:
                # 合并本地修改（如果有）
                for new_user in content:
                    existing = next((u for u in self.users if u['username'] == new_user['username']), None)
                    if existing and 'devices' in existing:
                        new_user['devices'] = existing['devices']
                self.users = content
            else:
                # 初始化数据明确为列表
                self.users = [{
                    "username": "18834877423",
                    "password": self.hash_password("123456").decode(),
                    "role": "admin",
                    "created_at": str(datetime.datetime.now())
                }]
                self.save_users()  # 确保保存格式正确
            
        except Exception as e:
            logging.error(f"数据刷新失败: {str(e)}")
            messagebox.showerror("加载错误", 
                f"加载用户数据失败: {str(e)}\n"
                "可能原因:\n"
                "1. GitHub文件格式不正确\n"
                "2. 网络连接问题\n"
                "3. 权限不足")
            raise
        
    def save_users(self):

    
        try:
            content = json.dumps(self.users, ensure_ascii=False)
            # 需要repo范围的写入权限
            if not self._github_api_update_file(content): 
                print("错误：GitHub API更新失败，请检查令牌权限")
        except Exception as e:
            print(f"保存失败：{str(e)}")


            # 验证数据格式
            if not isinstance(self.users, list):
                raise ValueError("用户数据必须为列表")
            for user in self.users:
                if not isinstance(user, dict):
                    raise ValueError(f"无效用户数据: {type(user)}")
        
            content = json.dumps(self.users, 
                            indent=4,
                            ensure_ascii=False,
                            default=str)
        
            # 记录保存内容
            logging.debug(f"准备保存的用户数据: {content[:200]}...")
        
            sha = self._get_file_sha()
            self._github_api_update_file(content, sha)
        except Exception as e:
            messagebox.showerror("保存错误", f"保存失败: {str(e)}")
            raise

    
    def update_password(self, username, new_password, old_password=None):
        for user in self.users:
            if user['username'] == username:
                if old_password and not self.check_password(old_password, user['password']):
                    raise ValueError("旧密码错误")
                
                if len(new_password) < 6:
                    raise ValueError("密码至少需要6位")
                
                # 密码历史检查（保留最近3次）
                password_history = user.get('password_history', [])
                new_hash = self.hash_password(new_password).decode()
                if any(self.check_password(new_password, ph) for ph in password_history[-3:]):
                    raise ValueError("不能使用最近3次用过的密码")
                
                # 更新数据
                password_history.append(user['password'])
                user['password'] = new_hash
                user['password_history'] = password_history[-3:]
                user['password_updated'] = str(datetime.datetime.now())
                self.save_users()
                return True
        raise ValueError("用户不存在")

    def _get_file_sha(self):
        """获取文件当前 SHA 标识"""
        headers = {'Authorization': f'token {self.access_token}'}
        url = f'https://api.github.com/repos/{self.repo_owner}/{self.repo_name}/contents/{self.file_path}'
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()['sha']
        return None

    def _github_api_update_file(self, content, sha=None):
        """通过 GitHub API 更新文件"""
        headers = {'Authorization': f'token {self.access_token}'}
        url = f'https://api.github.com/repos/{self.repo_owner}/{self.repo_name}/contents/{self.file_path}'
        
        data = {
            "message": "Update users data",
            "content": base64.b64encode(content.encode()).decode('utf-8'),
            "branch": "main"
        }
        if sha:
            data["sha"] = sha
            
        response = requests.put(url, headers=headers, json=data)
        if response.status_code not in [200, 201]:
            raise Exception(f"GitHub API 错误: {response.json().get('message', '未知错误')}")

    def _github_api_get_file(self):
        headers = {'Authorization': f'token {self.access_token}'}
        url = f'https://api.github.com/repos/{self.repo_owner}/{self.repo_name}/contents/{self.file_path}'
    
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()  # 处理4xx/5xx错误

            if response.status_code == 200:
                content_data = response.json()
                content = base64.b64decode(content_data['content']).decode('utf-8')
                parsed_data = json.loads(content)
                if not isinstance(parsed_data, list):
                    raise ValueError("用户数据格式错误：应为列表")
                return parsed_data
            elif response.status_code == 404:
                return None
            else:
                raise Exception(f"GitHub API错误: {response.status_code}")
            
        except requests.exceptions.RequestException as e:
            error_msg = f"网络请求失败: {str(e)}"
            if e.response:
                error_msg += f" (HTTP {e.response.status_code})"
            raise Exception(error_msg)
        except json.JSONDecodeError as e:
            raise Exception(f"JSON解析失败: {str(e)}")
        
    def add_device(self, username, device_info):
        """添加设备信息（子账号仅限首次绑定）"""
        for user in self.users:
            if user['username'] == username:
                # 管理员账号不限制设备
                if user['role'] == 'admin':
                    if not any(d['device_id'] == device_info['device_id'] 
                             for d in user['devices']):
                        user['devices'].append(device_info)
                        user['last_login'] = str(datetime.datetime.now())
                        self._save_with_retry()
                    return True
                # 普通用户只能绑定一个设备
                else:
                    if not user['devices']:  # 首次登录
                        user['devices'] = [device_info]
                        user['last_login'] = str(datetime.datetime.now())
                        self._save_with_retry()
                        return True
                    # 非首次登录检查设备
                    return any(d['device_id'] == device_info['device_id']
                             for d in user['devices'])
        return False
    
    def _save_with_retry(self, max_retries=3):
        """带重试的保存机制"""
        for attempt in range(max_retries):
            try:
                current_sha = self._get_file_sha()
                content = json.dumps(self.users, indent=2, ensure_ascii=False)
                if self._github_api_update_file(content, current_sha):
                    return True
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 409:
                    logging.warning(f"版本冲突，正在重试({attempt+1}/{max_retries})...")
                    self._force_load_users()  # 重新加载最新数据
                    time.sleep(1)
                    continue
                raise
            except Exception as e:
                logging.error(f"保存失败: {str(e)}")
                time.sleep(2)
        return False

    def remove_device(self, username, device_id):
        """移除设备"""
        for user in self.users:
            if user['username'] == username:
                user['devices'] = [d for d in user['devices']
                                 if d['device_id'] != device_id]
                self.save_users()
                return True
        return False

class ChangePasswordDialog:
    def __init__(self, parent, user_manager, username, is_admin=False):
        self.parent = parent
        self.user_manager = user_manager
        self.username = username
        self.is_admin = is_admin
        self.access_token = os.environ.get("GITHUB_TOKEN")
        
        self.top = tk.Toplevel(parent)
        self.top.title("修改密码")
        self.top.geometry("350x200")
        self._create_widgets()

        if not self.access_token:
            raise ValueError(
                "GitHub Token未配置！\n"
                "请按以下步骤操作：\n"
                "1. 打开终端\n"
                "2. 输入：export GITHUB_TOKEN=你的token\n"
                "3. 重新运行程序"
            )
    
    def _create_widgets(self):
        if not self.is_admin:
            ttk.Label(self.top, text="旧密码：").grid(row=0, column=0, padx=10, pady=5)
            self.old_pw = ttk.Entry(self.top, show="*")
            self.old_pw.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(self.top, text="新密码：").grid(row=1, column=0, padx=10, pady=5)
        self.new_pw = ttk.Entry(self.top, show="*")
        self.new_pw.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(self.top, text="确认密码：").grid(row=2, column=0, padx=10, pady=5)
        self.confirm_pw = ttk.Entry(self.top, show="*")
        self.confirm_pw.grid(row=2, column=1, padx=5, pady=5)
        
        btn_frame = ttk.Frame(self.top)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(btn_frame, text="提交", command=self._on_submit).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="取消", command=self.top.destroy).pack(side=tk.LEFT, padx=5)
    
    def _on_submit(self):
        old_password = self.old_pw.get() if not self.is_admin else None
        new_password = self.new_pw.get()
        confirm_password = self.confirm_pw.get()
        
        try:
            if new_password != confirm_password:
                raise ValueError("新密码不一致")
            
            self.user_manager.update_password(
                self.username,
                new_password,
                old_password=old_password
            )
            messagebox.showinfo("成功", "密码修改成功", parent=self.top)
            self.top.destroy()
        except Exception as e:
            messagebox.showerror("错误", str(e), parent=self.top)

# ------------------------- 登录对话框 -------------------------
class LoginDialog:
    def __init__(self, parent):
        self.parent = parent
        self.user_manager = UserManager()
        self.top = tk.Toplevel(parent)
        self.top.title("用户登录")
        self.top.geometry("320x280")  # 调整窗口尺寸
        self.top.resizable(False, False)
        self.user = None
        self._create_widgets()
        self._style_config()  # 新增样式配置方法
    
    def _style_config(self):
        """配置控件样式"""
        style = ttk.Style()
        style.configure('Login.TFrame', background='#F5F7F9')
        style.configure('Login.TLabel', 
                      background='#F5F7F9',
                      font=('微软雅黑', 10))
        style.configure('Login.TEntry',
                      fieldbackground='white',
                      bordercolor='#D1D5DB',
                      lightcolor='#D1D5DB',
                      darkcolor='#D1D5DB')
        style.map('Accent.TButton',
                foreground=[('active', 'white'), ('!active', 'white')],
                background=[('active', '#1E6BAF'), ('!active', '#2E86C1')])
        
        style.configure('Remember.TCheckbutton',
                        background='#F5F7F9',
                        font=('微软雅黑', 9),
                        relief='ridge',        # 添加边框
                        bordercolor='#CBD5E0')  # 浅灰色边框
        style.map('Remember.TCheckbutton',
                  background=[('active', '#F5F7F9')],
                  indicatormargin=[('!pressed', 2)])  # 调整勾选框间距
    
    def _create_widgets(self):
        main_frame = ttk.Frame(self.top, style='Login.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 标题
        ttk.Label(main_frame, text="欢迎登录", style='Login.TLabel',
                font=('微软雅黑', 14, 'bold')).grid(row=0, column=0, columnspan=2, pady=10)
        
        # 用户名输入
        ttk.Label(main_frame, text="账号：", style='Login.TLabel').grid(
            row=1, column=0, padx=5, pady=5, sticky='e')
        self.username = ttk.Entry(main_frame, style='Login.TEntry')
        self.username.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
        
        # 密码输入
        ttk.Label(main_frame, text="密码：", style='Login.TLabel').grid(
            row=2, column=0, padx=5, pady=5, sticky='e')
        self.password = ttk.Entry(main_frame, show="*", style='Login.TEntry')
        self.password.grid(row=2, column=1, padx=5, pady=5, sticky='ew')
        
        # 记住密码复选框（带边框样式）
        self.remember_var = tk.BooleanVar(value=True)
        remember_check = ttk.Checkbutton(
            main_frame,
            text="记住密码",
            variable=self.remember_var,
            style='Remember.TCheckbutton'  # 新增专用样式
        )
        remember_check.grid(row=3, column=0, columnspan=2, pady=8, sticky='w')
        
        # 按钮框架
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        ttk.Button(btn_frame, text="登 录", style='Accent.TButton',
                 command=self._on_login, width=10).pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_frame, text="退 出", 
                 command=self.top.destroy, width=10).pack(side=tk.RIGHT, padx=8)
        
        # 加载保存的凭据
        self._load_saved_credentials()
        
        # 输入框宽度适配
        main_frame.columnconfigure(1, weight=1)
        
        # 回车绑定
        self.password.bind('<Return>', lambda e: self._on_login())

        # 新增密码存储方法
    def _save_credentials(self, username, password):
        """加密保存凭据到本地"""
        try:
            from cryptography.fernet import Fernet
            config_dir = os.path.join(os.path.expanduser('~'), '.textgenerator')
            os.makedirs(config_dir, exist_ok=True)
        
            # 生成或加载加密密钥
            key_file = os.path.join(config_dir, 'key.key')
            if not os.path.exists(key_file):
                key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(key)
            else:
                with open(key_file, 'rb') as f:
                    key = f.read()
        
            # 加密数据
            cipher_suite = Fernet(key)
            encrypted_pw = cipher_suite.encrypt(password.encode()).decode()
        
            config = {
                'username': username,
                'encrypted_pw': encrypted_pw,
                'remember': True
            }
        
            with open(os.path.join(config_dir, 'config.json'), 'w') as f:
                json.dump(config, f)
            
        except Exception as e:
            logging.error("保存凭据失败: %s", str(e))

    def _load_saved_credentials(self):
        """加载已保存的登录信息"""
        try:
            from cryptography.fernet import Fernet
            config_file = os.path.join(os.path.expanduser('~'), '.textgenerator', 'config.json')
            key_file = os.path.join(os.path.expanduser('~'), '.textgenerator', 'key.key')
        
            if os.path.exists(config_file) and os.path.exists(key_file):
                with open(config_file) as f:
                    config = json.load(f)
                with open(key_file, 'rb') as f:
                    key = f.read()
            
                cipher_suite = Fernet(key)
                decrypted_pw = cipher_suite.decrypt(config['encrypted_pw'].encode()).decode()
            
                self.username.insert(0, config['username'])
                self.password.insert(0, decrypted_pw)
                self.remember_var.set(True)
            
        except Exception as e:
            logging.error("加载保存的凭据失败: %s", str(e))

    def _clear_credentials(self):
        """清除保存的凭据"""
        config_file = os.path.join(os.path.expanduser('~'), '.textgenerator', 'config.json')
        try:
            if os.path.exists(config_file):
                os.remove(config_file)
        except Exception as e:
            logging.error("清除凭据失败: %s", str(e))

    
    def _on_login(self):
        username = self.username.get().strip()
        password = self.password.get()

        try:
            # 1. 检查GitHub连接
            self._check_github_connection()

            # 2. 获取用户数据（强制刷新）
            self.user_manager.load_users()  # 关键点：每次登录都加载最新数据

            # 3. 验证用户是否存在
            user = next((u for u in self.user_manager.users 
                       if u['username'] == username), None)
            if not user:
                raise ValueError("用户不存在")

            # 4. 检查账户锁定状态
            self._check_account_lock(user)

            # 5. 验证密码
            if not UserManager.check_password(password, user['password']):
                self._handle_failed_login(user)
                return

            # 6. 设备验证和记录
            current_device_id = str(uuid.getnode())
            user = self.user_manager.get_user(username)  # 获取最新数据

            if user['role'] == 'user':
                # 设备验证逻辑
                current_device_id = str(uuid.getnode())
                if not user['devices']:
                    # 首次登录绑定设备（仅子账号）
                    device_info = self._get_device_info()
                    if not self.user_manager.add_device(username, device_info):
                        raise Exception("设备信息保存失败")
                else:
                    # 检查设备是否匹配（仅子账号）
                    if not any(d['device_id'] == current_device_id 
                              for d in user['devices']):
                        raise ValueError("该账号已绑定其他设备，无法在此设备登录")

            # 7. 登录成功处理
            self._handle_successful_login(user, username)

            # 8. 记录设备信息
            device_info = self._get_device_info()
            if not self.user_manager.add_device(username, device_info):
                raise Exception("设备信息保存失败")

            # 9. 强制保存更新后的用户数据
            self.user_manager.save_users()  # 关键点：立即同步到GitHub

            # 10. 处理记住密码
            if self.remember_var.get():
                self._save_credentials(username, password)
            else:
                self._clear_credentials()

            self.top.destroy()

        except Exception as e:
            messagebox.showerror("登录错误", 
                f"{str(e)}\n"
                "可能原因：\n"
                "设备已经绑定，无法登陆\n",
                parent=self.top)
            logging.error("登录失败：%s", exc_info=True)

        # 主账号特殊处理（允许跳过设备绑定）
        if user['role'] == 'admin':
            logging.info("管理员登录，跳过设备绑定")
        else:
            if not user.get('devices'):
                if not self.user_manager.add_device(username, device_info):
                    raise Exception("设备绑定失败")
            else:
                current_device = str(uuid.getnode())
                if not any(d['device_id'] == current_device for d in user['devices']):
                    raise ValueError("该账号已绑定其他设备")

        

    # 辅助方法
    def _check_github_connection(self):
        """验证GitHub连接性"""
        try:
            test_connection = requests.get(
                "https://api.github.com",
                headers={'Authorization': f'token {self.user_manager.access_token}'},
                timeout=5
            )
            test_connection.raise_for_status()
        except requests.RequestException as e:
            error_msg = f"GitHub连接失败: {str(e)}"
            if isinstance(e, requests.HTTPError):
                error_msg += f" (HTTP {e.response.status_code})"
            raise Exception(error_msg)

    def _check_account_lock(self, user):
        """检查账户锁定状态"""
        if user.get('locked_until'):
            lock_time = datetime.datetime.fromisoformat(user['locked_until'])
            if datetime.datetime.now() < lock_time:
                remain = (lock_time - datetime.datetime.now()).seconds // 60
                raise ValueError(f"账户已锁定，剩余时间：{remain}分钟")

    def _handle_failed_login(self, user):
        """处理登录失败"""
        user['failed_attempts'] = user.get('failed_attempts', 0) + 1
    
        if user['failed_attempts'] >= self.user_manager.max_attempts:
            user['locked_until'] = str(datetime.datetime.now() + 
                                    datetime.timedelta(seconds=self.user_manager.lock_duration))
            self.user_manager.save_users()
            raise ValueError("连续登录失败，账户已锁定5分钟")
    
        self.user_manager.save_users()
        raise ValueError(f"密码错误，剩余尝试次数：{self.user_manager.max_attempts - user['failed_attempts']}")

    def _handle_successful_login(self, user, username):
        """处理成功登录"""
        user['failed_attempts'] = 0
        user['last_login'] = str(datetime.datetime.now())
        self.user = user
        logging.info("用户 %s 登录成功，设备信息已记录", username)

    def _get_device_info(self):
        """确保返回基本设备信息，即使部分数据获取失败"""
        base_info = {
            "device_id": str(uuid.getnode()),
            "platform": platform.platform(),
            "login_time": str(datetime.datetime.now()),
            "ip": "0.0.0.0"  # 默认值
        }
    
        try:
            base_info["ip"] = requests.get('https://api.ipify.org', timeout=3).text
        except Exception as e:
            logging.warning(f"IP获取失败: {str(e)}")
    
        try:
            base_info["resolution"] = f"{self.top.winfo_screenwidth()}x{self.top.winfo_screenheight()}"
        except tk.TclError:
            base_info["resolution"] = "未知分辨率"
    
        try:
            base_info["browser"] = self._get_browser_info()
        except Exception as e:
            base_info["browser"] = "未知浏览器"
    
        return base_info  # 确保始终返回有效字典

def _get_browser_info(self):
    """安全获取浏览器信息"""
    try:
        # 通用浏览器检测
        from shutil import which
        chrome_path = which('google-chrome') or which('chrome') or which('chromium')
        if chrome_path:
            return chrome_path

        # 平台特定回退
        if sys.platform == 'win32':
            common_paths = [
                os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
                os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe")
            ]
        elif sys.platform == 'darwin':
            common_paths = ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome']
        else:
            common_paths = [
                '/usr/bin/google-chrome-stable',
                '/usr/bin/chromium',
                '/usr/bin/chromium-browser'
            ]

        for path in common_paths:
            if os.path.exists(path):
                return path

        return "Browser detection failed"
    except Exception as e:
        logging.debug(f"Browser detection error: {str(e)}")
        return "Unknown"

        

# ------------------------- 子账号管理 -------------------------
class SubAccountManager:
    def __init__(self, parent, user_manager):
        self.parent = parent
        self.user_manager = user_manager
        self.top = tk.Toplevel(parent)
        self.top.title("子账号管理")
        self._create_widgets()
    
    def _create_widgets(self):
        # 用户列表
        columns = ("用户名", "角色", "设备绑定", "最后登录")
        self.tree = ttk.Treeview(self.top, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 操作按钮
        btn_frame = ttk.Frame(self.top)
        btn_frame.pack(pady=5)
        
        ttk.Button(btn_frame, text="添加", command=self._add_user).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="删除", command=self._delete_user).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="改密", command=self._change_password).pack(side=tk.LEFT, padx=5)
        
        self._load_data()
    
    def _load_data(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for user in self.user_manager.users:
            if user['role'] != 'admin':
                # 获取设备状态
                device_status = "已绑定" if user.get('devices') else "未绑定"
                last_login = max(
                    [d['login_time'] for d in user.get('devices', [])],
                    default="从未登录"
                )
                
                self.tree.insert("", "end", values=(
                    user['username'],
                    user['role'],
                    device_status,
                    last_login
                ))

        # 添加右键菜单查看设备详情
        self.tree.bind("<Button-3>", self._show_device_detail)

    def _show_device_detail(self, event):
        """显示设备详情"""
        if not (selected := self.tree.selection()):
            return
        
        username = self.tree.item(selected[0], 'values')[0]
        user = next(u for u in self.user_manager.users 
                  if u['username'] == username)
        
        # 创建详情窗口
        detail_win = tk.Toplevel(self.top)
        detail_win.title(f"{username} - 设备详情")
        
        columns = ("设备ID", "平台", "IP地址", "最后登录")
        tree = ttk.Treeview(detail_win, columns=columns, show="headings")
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=120)
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 添加删除按钮
        def remove_device():
            if not (selected := tree.selection()):
                return
            device_id = tree.item(selected[0], 'values')[0]
            self.user_manager.remove_device(username, device_id)
            detail_win.destroy()
            self._show_device_detail(event)  # 刷新
        
        btn_frame = ttk.Frame(detail_win)
        btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="移除设备", command=remove_device).pack()
        
        # 填充数据
        for device in user.get('devices', []):
            tree.insert("", "end", values=(
                device['device_id'],
                device['platform'],
                device['ip'],
                device['login_time']
            ))

        # 添加管理员解绑按钮
        if self.parent.user['role'] == 'admin':  # 仅管理员可见
            def force_unbind():
                user['devices'] = []
                self.user_manager.save_users()
                detail_win.destroy()
                messagebox.showinfo("解绑成功", "设备绑定已重置，用户下次登录可绑定新设备")
        
            ttk.Button(btn_frame, text="强制解绑", 
                     command=force_unbind).pack(side=tk.LEFT, padx=5)
    
    def _add_user(self):
        AddUserDialog(self.top, self.user_manager, self._load_data)
    
    def _delete_user(self):
        if not (selected := self.tree.selection()):
            return
        username = self.tree.item(selected[0], 'values')[0]
        self.user_manager.users = [u for u in self.user_manager.users if u['username'] != username]
        self.user_manager.save_users()
        self._load_data()
    
    def _change_password(self):
        if not (selected := self.tree.selection()):
            return
        username = self.tree.item(selected[0], 'values')[0]
        ChangePasswordDialog(
            self.top,
            self.user_manager,
            username,
            is_admin=True
        )

# ------------------------- 添加用户对话框 -------------------------
class AddUserDialog:
    def __init__(self, parent, user_manager, callback):
        self.parent = parent
        self.user_manager = user_manager
        self.callback = callback
        
        self.top = tk.Toplevel(parent)
        self.top.title("添加用户")
        self._create_widgets()
    
    def _create_widgets(self):
        ttk.Label(self.top, text="用户名：").grid(row=0, column=0, padx=10, pady=5)
        self.username = ttk.Entry(self.top)
        self.username.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(self.top, text="密码：").grid(row=1, column=0, padx=10, pady=5)
        self.password = ttk.Entry(self.top, show="*")
        self.password.grid(row=1, column=1, padx=5, pady=5)
        
        btn_frame = ttk.Frame(self.top)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        ttk.Button(btn_frame, text="提交", command=self._on_submit).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="取消", command=self.top.destroy).pack(side=tk.LEFT, padx=5)
    
    def _on_submit(self):
        username = self.username.get()
        password = self.password.get()
        
        try:
            if not username or not password:
                raise ValueError("用户名和密码不能为空")
            if len(password) < 6:
                raise ValueError("密码至少需要6位")
            if any(u['username'] == username for u in self.user_manager.users):
                raise ValueError("用户名已存在")
            
            self.user_manager.users.append({
                "username": username,
                "password": UserManager.hash_password(password).decode(),
                "role": "user",
                "created_at": str(datetime.datetime.now())
            })
            self.user_manager.save_users()
            self.callback()
            self.top.destroy()
        except Exception as e:
            messagebox.showerror("错误", str(e), parent=self.top)

class TextGeneratorPro:
    def __init__(self, root, user):
        self.root = root
        self.user = user
        self.active = True
        self._init_ui()  # 合并初始化方法
        self._init_data()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._process_queue)
        self.lock = threading.Lock()

    def _init_ui(self):
        """合并后的界面初始化方法"""
        self.root.title(f"智能文本生成器 - {self.user['username']}")
        self.root.geometry("1400x900")
        
        # 初始化样式
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('.', 
                           background='#F5F7F9',
                           foreground='#2D3436',
                           font=('微软雅黑', 10))
        self.style.configure('TNotebook.Tab', padding=(20,5))
        self.style.configure('Accent.TButton', 
                           foreground='white', 
                           background='#2E86C1',
                           padding=6)
        
        # 创建菜单栏
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)
        
        # 用户菜单
        user_menu = tk.Menu(self.menu_bar, tearoff=0)
        user_menu.add_command(label="修改密码", command=self._change_password)
        user_menu.add_separator()
        user_menu.add_command(label="退出", command=self.root.destroy)
        self.menu_bar.add_cascade(label="用户", menu=user_menu)
        
        # 管理员菜单
        if self.user['role'] == 'admin':
            admin_menu = tk.Menu(self.menu_bar, tearoff=0)
            admin_menu.add_command(label="子账号管理", 
                                command=lambda: SubAccountManager(self.root, UserManager()))
            self.menu_bar.add_cascade(label="管理", menu=admin_menu)
        
        # 主内容框架
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 创建Notebook（标签页容器）
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # 添加各标签页
        self.create_tab("title", "标题生成", 10)
        self.create_tab("keyword", "关键词处理", 10)
        self.create_tab("point", "要点处理", 5)
        self.create_tab("text", "文案处理", 5)
        self.create_summary_tab()
        
        # 状态栏和进度条
        self.status = ttk.Label(main_frame, text="就绪", anchor=tk.W)
        self.status.pack(fill=tk.X, pady=5)
        self.progress = ttk.Progressbar(main_frame, mode='determinate')
        self.progress.pack(fill=tk.X)

    def _init_data(self):
        self.task_queue = queue.Queue()
        self.comb_cache = deque(maxlen=5000)
        self.title_data = []
        self.keyword_data = []
        self.point_data = []
        self.text_data = []
        self.running = False  # 添加运行状态初始化
    
    def _change_password(self):
        """修改密码时刷新数据"""
        self.user_manager._force_load_users()
        ChangePasswordDialog(
            self.root,
            self.user_manager,
            self.user['username'],
            is_admin=False
        )
        self.user_manager._force_load_users()  # 修改后刷新数据
    
    def _process_queue(self):
        if not self.active:
            return
        try:
            while True:
                task = self.task_queue.get_nowait()
                # 处理任务类型
                if task[0] == 'progress':
                    current, total = task[1], task[2]
                    self.progress['value'] = current * 100 // total
                elif task[0] == 'result':
                    tab_id, data = task[1], task[2]
                    output = getattr(self, f"{tab_id}_output")
                    output.config(state=tk.NORMAL)
                    output.delete('1.0', tk.END)
                    output.insert(tk.END, '\n\n'.join(data))
                    output.config(state=tk.DISABLED)
                    # 更新对应数据列表
                    getattr(self, f"{tab_id}_data").extend(data)
                    self.update_summary_table()  # 同步汇总表格
                elif task[0] == 'error':
                    messagebox.showerror("生成错误", task[1])
                elif task[0] == 'done':
                    self.running = False
                    self.status.config(text="就绪")
                    self.progress['value'] = 100
        except queue.Empty:
            pass
        finally:
            if self.active:
                self.root.after(100, self._process_queue)
    
    def _on_close(self):
        self.active = False
        self.root.destroy()
        
        # 线程控制
        self.task_queue = queue.Queue()
        self.running = False
        self.lock = threading.Lock()
        
        # 初始化界面
        self.init_ui()
        self.init_styles()  # 确保调用
        self.set_sample_data()
        self.root.after(100, self.process_queue)

    def init_styles(self):  # 补全缺失的方法
        """初始化界面样式"""
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('.', 
                          background='#F5F7F9',
                          foreground='#2D3436',
                          font=('微软雅黑', 10))
        self.style.configure('TNotebook.Tab', padding=(20,5))
        self.style.configure('Accent.TButton', 
                          foreground='white', 
                          background='#2E86C1',
                          padding=6)

    def update_summary_table(self):  # 确保保留原有方法
        """同步数据到汇总表格"""
        max_rows = max(
            len(self.title_data),
            len(self.keyword_data),
            len(self.point_data),
            len(self.text_data)
        )
    
        self.tree.delete(*self.tree.get_children())
        for idx in range(max_rows):
            self.tree.insert("", "end", values=(
                idx + 1,
                self.title_data[idx] if idx < len(self.title_data) else "",
                self.keyword_data[idx] if idx < len(self.keyword_data) else "",
                self.point_data[idx] if idx < len(self.point_data) else "",
                self.text_data[idx] if idx < len(self.text_data) else ""
            ))
    
    def init_ui(self):
        """构建主界面"""
        # 添加菜单栏
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)

        # 用户菜单（所有用户可见）
        user_menu = tk.Menu(self.menu_bar, tearoff=0)
        user_menu.add_command(label="修改密码", command=self.show_change_password)
        self.menu_bar.add_cascade(label="用户", menu=user_menu)
        
        # 如果是管理员，添加账户管理菜单
        if self.user['role'] == 'admin':
            account_menu = tk.Menu(self.menu_bar, tearoff=0)
            account_menu.add_command(label="子账号管理", command=self.show_sub_account_manager)
            self.menu_bar.add_cascade(label="账户管理", menu=account_menu)
        
        
        # 原有界面组件
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.create_tab("title", "标题生成", 10)
        self.create_tab("keyword", "关键词处理", 10)
        self.create_tab("point", "要点处理", 5)
        self.create_tab("text", "文案处理", 5)
        self.create_summary_tab()
        
        self.status = ttk.Label(main_frame, text="就绪", anchor=tk.W)
        self.status.pack(fill=tk.X, pady=5)
        
        self.progress = ttk.Progressbar(main_frame, mode='determinate')
        self.progress.pack(fill=tk.X)

    def show_change_password(self):
        """显示修改密码对话框"""
        ChangePasswordDialog(
            self.root,
            UserManager(),
            self.user
        )

    def show_sub_account_manager(self):
        """显示子账号管理窗口"""
        SubAccountManager(self.root)

    def create_tab(self, tab_id, name, default_length):
        """创建处理标签页模板"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=name)
        
        # 输入区
        input_frame = ttk.LabelFrame(tab, text=f"输入{name}内容（每行一项）")
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.input_area = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=8)
        self.input_area.pack(fill=tk.BOTH, expand=True)
        setattr(self, f"{tab_id}_input", self.input_area)
        
        # 控制面板
        ctrl_frame = ttk.Frame(tab)
        ctrl_frame.pack(pady=10)
        
        ttk.Label(ctrl_frame, text="生成数量：").pack(side=tk.LEFT)
        self.count_entry = ttk.Entry(ctrl_frame, width=8)
        self.count_entry.insert(0, "50")
        self.count_entry.pack(side=tk.LEFT, padx=5)
        setattr(self, f"{tab_id}_count", self.count_entry)
        
        ttk.Label(ctrl_frame, text="组合长度：").pack(side=tk.LEFT)
        self.length_entry = ttk.Entry(ctrl_frame, width=8)
        self.length_entry.insert(0, str(default_length))
        self.length_entry.pack(side=tk.LEFT, padx=5)
        setattr(self, f"{tab_id}_length", self.length_entry)
        
        ttk.Button(ctrl_frame, text="生成", style='Accent.TButton',
                 command=lambda: self.start_generate(tab_id)).pack(side=tk.LEFT, padx=10)
        ttk.Button(ctrl_frame, text="清空", 
                 command=lambda: self.clear_tab(tab_id)).pack(side=tk.LEFT)
        # 添加导出按钮
        ttk.Button(ctrl_frame, text="导出Excel", style='Accent.TButton',
                 command=lambda: self.export_to_excel(tab_id)).pack(side=tk.LEFT, padx=10)
        
        # 输出区
        output_frame = ttk.LabelFrame(tab, text="处理结果")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.output_area = scrolledtext.ScrolledText(output_frame, state=tk.DISABLED)
        self.output_area.pack(fill=tk.BOTH, expand=True)
        setattr(self, f"{tab_id}_output", self.output_area)

    def export_to_excel(self, tab_id):
        """导出当前标签页结果到Excel"""
        output_widget = getattr(self, f"{tab_id}_output")
        content = output_widget.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("警告", "没有内容可导出")
            return
        
        # 解析内容（根据两个换行符分隔条目）
        items = content.split('\n\n')
        
        # 获取保存路径
        file_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel 文件", "*.xlsx"), ("所有文件", "*.*")]
        )
        if not file_path:
            return
        
        try:
            import pandas as pd
            # 根据标签页类型设置列名
            column_map = {
                "title": "标题",
                "keyword": "关键词",
                "point": "要点",
                "text": "文案"
            }
            df = pd.DataFrame(items, columns=[column_map[tab_id]])
            df.to_excel(file_path, index=False)
            messagebox.showinfo("导出成功", f"文件已保存至：{file_path}")
        except ImportError:
            messagebox.showerror("依赖缺失", "请安装pandas和openpyxl库以支持导出功能")
        except Exception as e:
            messagebox.showerror("导出错误", str(e))

    def start_generate(self, tab_id):
        """启动生成任务"""
        if self.running:
            return
            
        try:
            input_widget = getattr(self, f"{tab_id}_input")
            lines = [line.strip() for line in input_widget.get("1.0", tk.END).splitlines() if line.strip()]
            count = int(getattr(self, f"{tab_id}_count").get())
            length = int(getattr(self, f"{tab_id}_length").get())
        
            if not lines:
                messagebox.showerror("错误", "输入内容不能为空")
                return
            if length > len(lines):
                messagebox.showerror("错误", f"组合长度不能超过{len(lines)}")
                return
            
            self.running = True
            self.progress['value'] = 0
            self.status.config(text="生成中...")
        
            # 关键修复：传递所有参数
            threading.Thread(
                target=self.generate_combinations,
                args=(tab_id, lines, count, length),  # 确保参数完整
                daemon=True
            ).start()
        
        except ValueError:
            messagebox.showerror("输入错误", "请输入有效的数字")

    def generate_combinations(self, tab_id, lines, count, length):
        try:
            with self.lock:
                self.comb_cache.clear()
                generated = 0
                max_attempts = count * 100
            
                for _ in range(max_attempts):
                    sample = random.sample(lines, length)
                    if tab_id == 'title':
                        combination = ' '.join(sample)
                    else:
                        combination = '\n'.join(sample)
                
                    if combination not in self.comb_cache:
                        self.comb_cache.append(combination)
                        generated += 1
                        # 提交进度更新
                        self.task_queue.put(('progress', generated, count))
                
                    if generated >= count:
                        break
            
                # 提交生成结果
                self.task_queue.put(('result', tab_id, list(self.comb_cache)[:count]))
        except Exception as e:
            self.task_queue.put(('error', str(e)))
        finally:
            self.task_queue.put(('done',))

    def process_queue(self):
        try:
            while True:
                try:
                    task = self.task_queue.get_nowait()
                    if task[0] == 'result':
                        tab_id, data = task[1], task[2]
                        output = getattr(self, f"{tab_id}_output")
                        output.config(state=tk.NORMAL)
                        output.delete('1.0', tk.END)
                        output.insert(tk.END, '\n\n'.join(data))
                        output.config(state=tk.DISABLED)
                        output.update_idletasks() 
                        # 存储数据到对应列表
                        getattr(self, f"{tab_id}_data").extend(data)
                        # 新增同步代码
                        self.update_summary_table()
        
                    task = self.task_queue.get_nowait()
                    if task[0] == 'progress':
                        current, total = task[1], task[2]
                        self.progress['value'] = current * 100 // total
                    elif task[0] == 'result':
                        tab_id, data = task[1], task[2]
                        output = getattr(self, f"{tab_id}_output")
                        output.config(state=tk.NORMAL)
                        output.delete('1.0', tk.END)
                        output.insert(tk.END, '\n\n'.join(data))
                        output.config(state=tk.DISABLED)
                    elif task[0] == 'error':
                        messagebox.showerror("生成错误", task[1])
                    elif task[0] == 'done':
                        self.running = False
                        self.status.config(text="就绪")
                        self.progress['value'] = 100
                except queue.Empty:
                    break
        finally:
            self.root.after(100, self.process_queue)

    def create_summary_tab(self):
        """数据汇总表格"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="数据汇总")
    
        # 控制按钮栏
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(pady=5)
    
        # 添加清空按钮
        ttk.Button(btn_frame, text="清空数据", style='Accent.TButton',
                 command=self.clear_summary_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="导出Excel", style='Accent.TButton',
                 command=self.export_summary_to_excel).pack(side=tk.LEFT, padx=5)
    
        # 原有树状图创建代码...
        columns = ("ID", "标题", "关键词", "要点", "文案")
        self.tree = ttk.Treeview(tab, columns=columns, show='headings', selectmode='browse')
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150, anchor=tk.W)
            
        vsb = ttk.Scrollbar(tab, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tab, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
    
    def clear_summary_data(self):
        """清空所有数据和汇总表格"""
        # 清空Treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
    
        # 清空数据存储列表
        self.title_data.clear()
        self.keyword_data.clear()
        self.point_data.clear()
        self.text_data.clear()
    
        # 清空各标签页输出区域
        for tab_id in ["title", "keyword", "point", "text"]:
            output = getattr(self, f"{tab_id}_output")
            output.config(state=tk.NORMAL)
            output.delete('1.0', tk.END)
            output.config(state=tk.DISABLED)
    
        # 更新状态提示
        self.status.config(text="所有数据已清空")
        self.progress['value'] = 0
        messagebox.showinfo("操作成功", "所有数据已成功清空")

    def export_summary_to_excel(self):
        """动态处理要点列分列"""
        try:
            # 获取当前要点处理的组合元素数量
            point_length = int(self.point_length.get())  # 假设要点处理标签页有组合长度输入框
        
            # 动态生成列头
            columns = ["ID", "标题", "关键词"]
            columns += [f"要点处理{i+1}" for i in range(point_length)]
            columns.append("文案")
        
            # 获取数据
            data = []
            max_rows = max(len(self.title_data), len(self.keyword_data),
                          len(self.point_data), len(self.text_data))
        
            for idx in range(max_rows):
                # 处理要点分列
                point_values = []
                if idx < len(self.point_data):
                    parts = self.point_data[idx].split('\n')[:point_length]
                    parts += [''] * (point_length - len(parts))
                    point_values = parts
            
                row = [
                    idx + 1,
                    self.title_data[idx] if idx < len(self.title_data) else '',
                    self.keyword_data[idx] if idx < len(self.keyword_data) else '',
                    *point_values,  # 展开分列后的要点值
                    self.text_data[idx] if idx < len(self.text_data) else ''
                ]
                data.append(row)

            # 导出到Excel
            file_path = filedialog.asksaveasfilename(
                defaultextension=".xlsx",
                filetypes=[("Excel文件", "*.xlsx")],
                initialfile="文本生成结果"
            )
            if file_path:
                import pandas as pd
                df = pd.DataFrame(data, columns=columns)
                df.to_excel(file_path, index=False)
                messagebox.showinfo("导出成功", f"文件已保存至：\n{file_path}")
            
        except Exception as e:
            messagebox.showerror("导出错误", f"发生错误：{str(e)}")


    def set_sample_data(self):
        """设置示例数据"""
        

    def clear_tab(self, tab_id):
        """清空指定标签页内容"""
        input_widget = getattr(self, f"{tab_id}_input")
        output_widget = getattr(self, f"{tab_id}_output")
        
        input_widget.delete('1.0', tk.END)
        output_widget.config(state=tk.NORMAL)
        output_widget.delete('1.0', tk.END)
        output_widget.config(state=tk.DISABLED)

if __name__ == "__main__":
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass
    
    root = tk.Tk()
    root.withdraw()
    
    login = LoginDialog(root)
    root.wait_window(login.top)
    
    if login.user:
        main = tk.Tk()
        app = TextGeneratorPro(main, login.user)
        main.mainloop()
