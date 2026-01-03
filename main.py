from kivymd.app import MDApp
from kivymd.uix.screen import Screen
from kivymd.uix.button import MDFillRoundFlatButton, MDIconButton
from kivymd.uix.textfield import MDTextField
from kivymd.uix.filemanager import MDFileManager
from kivymd.uix.label import MDLabel
from kivymd.toast import toast
from kivymd.uix.bottomnavigation import MDBottomNavigation, MDBottomNavigationItem
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.scrollview import MDScrollView
from kivymd.uix.progressbar import MDProgressBar
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.utils import platform
import threading
import sys
import socket
import os

# Import your script logic
import napster 
from cryptography.fernet import Fernet

class NapsterApp(MDApp):
    def build(self):
        # Request Android Permissions
        if platform == 'android':
            from android.permissions import request_permissions, Permission
            request_permissions([Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE])

        self.theme_cls.primary_palette = "Blue"
        self.theme_cls.theme_style = "Dark"
        
        # Main Screen
        screen = Screen()
        
        # Bottom Navigation
        nav = MDBottomNavigation(selected_color_background="blue", text_color_active="lightgrey")
        
        # --- SEND TAB ---
        self.tab_send = MDBottomNavigationItem(
            name='screen 1',
            text='Send',
            icon='send',
        )
        
        # Layout for Send Tab
        send_layout = MDBoxLayout(orientation='vertical', padding=20, spacing=20, pos_hint={"center_x": 0.5, "center_y": 0.6})
        
        # IP Field with Scan Button
        ip_layout = MDBoxLayout(orientation='horizontal', spacing=10, size_hint_x=0.9, pos_hint={"center_x": 0.5})
        self.ip_input = MDTextField(hint_text="Receiver IP", size_hint_x=0.8, mode="rectangle")
        btn_scan = MDIconButton(icon="magnify", on_release=self.scan_ip)
        ip_layout.add_widget(self.ip_input)
        ip_layout.add_widget(btn_scan)
        
        self.key_input = MDTextField(hint_text="Encryption Key", password=True, size_hint_x=0.9, pos_hint={"center_x": 0.5}, mode="rectangle")
        self.file_label = MDLabel(text="No file selected", halign="center")
        
        btn_select = MDFillRoundFlatButton(text="Select File", pos_hint={"center_x": 0.5}, on_release=self.open_file_manager)
        btn_send = MDFillRoundFlatButton(text="SEND FILE", pos_hint={"center_x": 0.5}, on_release=self.send_file, font_size="18sp")
        
        # Progress Bar (Hidden by default)
        self.progress_bar = MDProgressBar(value=0, size_hint_x=0.9, pos_hint={"center_x": 0.5}, opacity=0)

        send_layout.add_widget(MDLabel(text="Send File", font_style="H5", halign="center"))
        send_layout.add_widget(ip_layout)
        send_layout.add_widget(self.key_input)
        send_layout.add_widget(self.file_label)
        send_layout.add_widget(btn_select)
        send_layout.add_widget(self.progress_bar) # Add Bar here
        send_layout.add_widget(btn_send)
        send_layout.add_widget(MDLabel()) # Spacer
        
        self.tab_send.add_widget(send_layout)
        
        # --- RECEIVE TAB ---
        self.tab_receive = MDBottomNavigationItem(
            name='screen 2',
            text='Receive',
            icon='download',
        )
        
        recv_layout = MDBoxLayout(orientation='vertical', padding=20, spacing=10)
        
        # Info Section
        local_ip = self.get_ip()
        recv_layout.add_widget(MDLabel(text="Receiver Status", font_style="H5", halign="center", size_hint_y=None, height=40))
        
        self.ip_label = MDTextField(text=local_ip, hint_text="Your IP Address", readonly=True, mode="rectangle")
        recv_layout.add_widget(self.ip_label)
        
        # EDITABLE Key for Receiver
        self.key_display = MDTextField(hint_text="Session Key (Paste Sender's Key)", mode="rectangle")
        recv_layout.add_widget(self.key_display)
        
        # Start/Stop Button
        self.btn_server = MDFillRoundFlatButton(text="START SERVER", pos_hint={"center_x": 0.5}, on_release=self.toggle_server)
        recv_layout.add_widget(self.btn_server)
        
        # Log View
        recv_layout.add_widget(MDLabel(text="Logs:", size_hint_y=None, height=30))
        
        scroll = MDScrollView(size_hint=(1, 1), do_scroll_x=False)
        self.log_label = MDLabel(text="Ready to start...", size_hint_y=None, markup=True)
        self.log_label.bind(texture_size=self.log_label.setter('size'))
        scroll.add_widget(self.log_label)
        
        recv_layout.add_widget(scroll)
        
        self.tab_receive.add_widget(recv_layout)
        
        # Add tabs to nav
        nav.add_widget(self.tab_send)
        nav.add_widget(self.tab_receive)
        screen.add_widget(nav)

        # File Manager Setup
        self.file_manager = MDFileManager(
            exit_manager=self.exit_manager,
            select_path=self.select_path,
        )
        self.selected_path = None
        
        # Receiver State
        self.receiver = None
        self.server_thread = None
        self.is_server_running = False
        
        return screen

    def on_start(self):
        # Try to init key after startup
        Clock.schedule_once(self.retry_init_key, 1)

    def retry_init_key(self, dt):
        try:
            self.init_key()
        except Exception as e:
            toast(f"Waiting for permissions... {e}")
            # Retry in 2 seconds
            Clock.schedule_once(self.retry_init_key, 2)

    def get_application_config_path(self):
        # Initial config path
        return super().get_application_config_path()

    def get_store_path(self):
        if platform == 'android':
            try:
                from jnius import autoclass
                PythonActivity = autoclass('org.kivy.android.PythonActivity')
                context = PythonActivity.mActivity
                # Get private external storage: /storage/emulated/0/Android/data/org.napster.../files/
                file_p = context.getExternalFilesDir(None)
                path = file_p.getAbsolutePath()
            except Exception as e:
                # Fallback if jnius fails (unlikely)
                print(f"Storage Error: {e}")
                path = "/data/data/org.napster.napster_p2p/files"
        else:
            path = os.path.expanduser("~/Documents/NapsterP2P")
            
        os.makedirs(path, exist_ok=True)
        return path

    def get_ip(self):
        try:
            h = socket.gethostname()
            return socket.gethostbyname(h)
        except:
            return "Unknown"

    def init_key(self):
        storage = self.get_store_path()
        key_path = os.path.join(storage, 'napster.key')
        
        if os.path.exists(key_path):
            with open(key_path, 'rb') as f:
                key = f.read().strip()
        else:
            key = Fernet.generate_key()
            with open(key_path, 'wb') as f:
                f.write(key)
        
        self.current_key = key
        self.key_input.text = key.decode()
        self.key_display.text = key.decode()

    # --- SERVER LOGIC ---
    def toggle_server(self, instance):
        if self.is_server_running:
            self.stop_server()
        else:
            self.start_server()

    def start_server(self):
        if self.is_server_running: return
        
    def start_server(self):
        if self.is_server_running: return
        
        # Save to Public Download Folder on Android (Native Java Call)
        if platform == 'android':
            try:
                from jnius import autoclass
                Environment = autoclass('android.os.Environment')
                # Get standard public Download directory
                path = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).getAbsolutePath()
                storage = path
            except Exception as e:
                self.log_message(f"Path Error: {e}")
                storage = self.get_store_path() # Fallback
        else:
            storage = self.get_store_path()
            
        recv_dir = os.path.join(storage, 'NapsterReceived') # Subfolder in Downloads
        os.makedirs(recv_dir, exist_ok=True)
        
        # Use Manual Key if edited
        user_key = self.key_display.text.strip().encode()
        if user_key:
            self.current_key = user_key
        
        self.log_message(f"Starting Server... (using key: {self.current_key[:5]}...)")
        self.log_message(f"Saving to: {recv_dir}") # Show user where file goes
        # Toast the location too
        Clock.schedule_once(lambda dt: toast(f"Saving to: {recv_dir}"))
        
        self.receiver = napster.Receiver(
            port=9999, 
            output_dir=recv_dir, 
            key=self.current_key,
            callback=self.msg_callback
        )
        
        self.server_thread = threading.Thread(target=self.receiver.start)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        self.is_server_running = True
        self.btn_server.text = "STOP SERVER"
        self.btn_server.md_bg_color = (1, 0, 0, 1) # Red

    def stop_server(self):
        if self.receiver:
            self.receiver.stop()
            self.log_message("Server Stopped.")
        
        self.is_server_running = False
        self.btn_server.text = "START SERVER"
        self.btn_server.md_bg_color = self.theme_cls.primary_color

    def msg_callback(self, msg):
        # Called from background thread
        Clock.schedule_once(lambda dt: self.log_message(msg))

    def log_message(self, msg):
        current_text = self.log_label.text
        if len(current_text) > 5000: # Truncate logs
             current_text = current_text[-4000:]
        self.log_label.text = current_text + "\n" + str(msg)

    # --- FILE MANAGER ---
    def open_file_manager(self, *args):
        if platform == 'android':
            from android.storage import primary_external_storage_path
            # Start in Download folder (Accessible on Pixel 6+)
            path = os.path.join(primary_external_storage_path(), 'Download')
        else:
            path = os.path.expanduser("~")
        self.file_manager.show(path) 

    def select_path(self, path):
        self.selected_path = path
        self.file_label.text = f"Selected: {os.path.basename(path)}"
        self.exit_manager()
        toast(path)

    def exit_manager(self, *args):
        self.file_manager.close()

    # --- PROGRESS CALLBACK ---
    def update_progress(self, percent):
        self.progress_bar.value = percent

    # --- SEND LOGIC ---
    def scan_ip(self, *args):
        toast("Scanning for Receiver...")
        def run_scan():
            found_ip = napster.discover_receivers(timeout=5)
            if found_ip:
                # Update UI on main thread
                def update_ui(dt):
                    self.ip_input.text = found_ip
                    toast(f"Found: {found_ip}")
                Clock.schedule_once(update_ui)
            else:
                Clock.schedule_once(lambda dt: toast("No Receiver found"))
        
        threading.Thread(target=run_scan).start()

    def send_file(self, *args):
        ip = self.ip_input.text
        key = self.key_input.text
        
        if not ip or not key or not self.selected_path:
            toast("Please fill all fields")
            return

        toast("Sending...")
        
        # Clean inputs
        clean_ip = ip.strip()
        clean_key = key.strip()

        # Reset Progress
        self.progress_bar.opacity = 1
        self.progress_bar.value = 0

        def run_send():
            try:
                # Basic validation
                if len(clean_key) == 0:
                    raise ValueError("Key is empty")

                # Define callback wrapper for main thread updates
                def progress_wrapper(p):
                     Clock.schedule_once(lambda dt: self.update_progress(p))

                res = napster.send_file_logic(clean_ip, self.selected_path, clean_key, progress_callback=progress_wrapper)
                
                def on_complete(dt):
                    toast(res)
                    self.progress_bar.opacity = 0 # Hide when done
                    
                Clock.schedule_once(on_complete)
            except Exception as e:
                 err_msg = str(e)
                 if "32 url-safe base64-encoded bytes" in err_msg:
                     err_msg = "Invalid Key Format (Check spaces?)"
                 
                 def on_error(dt):
                     toast(f"Error: {err_msg}")
                     self.progress_bar.opacity = 0

                 Clock.schedule_once(on_error)
            
        threading.Thread(target=run_send).start()

    def on_stop(self):
        self.stop_server()

if __name__ == "__main__":
    NapsterApp().run()
