import socket
import struct
import os
import argparse
import sys
import threading
import time
from cryptography.fernet import Fernet
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- Protocol Definition ---

class Protocol:
    MAGIC_BYTE = 0x01
    CHUNK_SIZE = 4096  # 4KB

    @staticmethod
    def pack_handshake(filename: str, filesize: int, cipher: Fernet) -> bytes:
        """
        Creates the handshake packet:
        [1 byte Magic] [4 bytes Name Len] [Name Bytes] [8 bytes File Size]
        
        V2 Encryption:
        The payload (Name Len + Name + Size) is encrypted.
        Structure:
        [1 byte Magic] [4 bytes Encrypted Payload Len] [Encrypted Payload]
        """
        encoded_name = filename.encode('utf-8')
        name_len = len(encoded_name)
        
        # Raw payload
        payload = struct.pack('!I', name_len) + encoded_name + struct.pack('!Q', filesize)
        
        # Encrypt payload
        encrypted_payload = cipher.encrypt(payload)
        encrypted_len = len(encrypted_payload)
        
        # Header
        header = struct.pack('!BI', Protocol.MAGIC_BYTE, encrypted_len)
        
        return header + encrypted_payload

    @staticmethod
    def unpack_handshake_header(sock: socket.socket, cipher: Fernet):
        """
        Reads the handshake. Decrypts metadata.
        Returns (filename, filesize).
        """
        # Read Magic (1) + Encrypted Len (4)
        header_data = Protocol.recv_all(sock, 5)
        if not header_data:
            return None, None
            
        magic, encrypted_len = struct.unpack('!BI', header_data)
        
        if magic != Protocol.MAGIC_BYTE:
            raise ValueError(f"Invalid magic byte: {magic}")
            
        # Read Encrypted Payload
        encrypted_payload = Protocol.recv_all(sock, encrypted_len)
        
        # Decrypt
        try:
            decrypted_payload = cipher.decrypt(encrypted_payload)
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
            
        # Unpack Payload: [4 bytes Name Len] [Name] [8 bytes Size]
        name_len = struct.unpack('!I', decrypted_payload[:4])[0]
        filename = decrypted_payload[4:4+name_len].decode('utf-8')
        filesize = struct.unpack('!Q', decrypted_payload[4+name_len:])[0]
        
        return filename, filesize

    @staticmethod
    def recv_all(sock: socket.socket, n: int) -> bytes:
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

# --- Receiver (Server) ---

class Receiver:
    def __init__(self, port=9999, output_dir='.', key=None, callback=None):
        self.port = port
        self.output_dir = output_dir
        self.cipher = Fernet(key)
        self.callback = callback  # Function(msg, logging_level)
        os.makedirs(output_dir, exist_ok=True)
        self.running = False
        self.sock = None
        self.broadcaster = Broadcaster()

    def log(self, msg):
        if self.callback:
            self.callback(msg)
        else:
            print(msg)

    def stop(self):
        self.running = False
        self.broadcaster.stop()
        if self.sock:
            try:
                self.sock.close()
            except:
                pass

    def start(self):
        self.running = True
        self.broadcaster.start()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            self.sock = s
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(('0.0.0.0', self.port))
            except OSError as e:
                self.log(f"Error binding to port {self.port}: {e}")
                return
                
            s.listen(5)
            self.log(f"[*] Listening on 0.0.0.0:{self.port}")
            self.log(f"[*] Saving to: {os.path.abspath(self.output_dir)}")

            while self.running:
                try:
                    conn, addr = s.accept()
                except:
                    break # Socket closed
                
                t = threading.Thread(target=self.handle_client, args=(conn, addr))
                t.daemon = True
                t.start()

    def handle_client(self, conn, addr):
        self.log(f"[+] Connection from {addr[0]}")
    def handle_client(self, conn, addr):
        self.log(f"[+] Connection from {addr[0]}")
        try:
            filename, filesize = Protocol.unpack_handshake_header(conn, self.cipher)
            if not filename:
                return
            
            safe_filename = os.path.basename(filename)
            final_path = os.path.join(self.output_dir, safe_filename)
            part_path = final_path + ".part"
            
            # --- RESUME LOGIC (The Tunnel) ---
            offset = 0
            if os.path.exists(part_path):
                offset = os.path.getsize(part_path)
                self.log(f"[*] Found partial file. Resuming from {offset} bytes.")
            elif os.path.exists(final_path):
                # File already exists? Maybe overwrite or rename. 
                # For sync, check size? For now, we overwrite if not .part
                # Or maybe we assume it's a new send.
                pass

            # Send Offset to Sender (8 bytes, Big Endian)
            conn.sendall(struct.pack('!Q', offset))
            
            if offset >= filesize:
                self.log(f"[*] File already complete on disk.")
                # We still need to drain the socket or handle end? 
                # If offset == filesize, sender should send 0 bytes.
            else:
                self.log(f"[*] Receiving '{filename}' (starting at {offset}/{filesize})...")

            received_bytes = offset
            
            # Open in APPEND mode if resuming, WRITE if new (offset 0)
            mode = 'ab' if offset > 0 else 'wb'
            
            with open(part_path, mode) as f:
                while True:
                    len_data = Protocol.recv_all(conn, 4)
                    if not len_data: 
                        break
                    
                    chunk_len = struct.unpack('!I', len_data)[0]
                    encrypted_chunk = Protocol.recv_all(conn, chunk_len)
                    
                    decrypted_chunk = self.cipher.decrypt(encrypted_chunk)
                    f.write(decrypted_chunk)
                    received_bytes += len(decrypted_chunk)
            
            # Rename .part to final if complete
            if received_bytes >= filesize:
                if os.path.exists(final_path):
                    os.remove(final_path)
                os.rename(part_path, final_path)
                self.log(f"[SUCCESS] Saved {final_path}")
            else:
                self.log(f"[WARN] Connection dropped at {received_bytes}/{filesize}")
            
        except Exception as e:
            self.log(f"[-] Error with {addr[0]}: {e}")
        finally:
            conn.close()

# --- Sender (Client) ---

class Sender:
    def __init__(self, target_ip, target_port=9999, key=None, callback=None):
        self.target_ip = target_ip
        self.target_port = target_port
        self.cipher = Fernet(key)
        self.callback = callback

    def send_file(self, filepath):
        if not os.path.exists(filepath):
            print(f"File not found: {filepath}")
            return

        filesize = os.path.getsize(filepath)
        filename = os.path.basename(filepath)

        print(f"[*] Sending '{filename}' to {self.target_ip}...")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((self.target_ip, self.target_port))
            except ConnectionRefusedError:
                print(f"Connection refused at {self.target_ip}")
                return

            # Handshake
            handshake = Protocol.pack_handshake(filename, filesize, self.cipher)
            s.sendall(handshake)

            # --- RESUME LOGIC (The Tunnel) ---
            # Wait for Offset from Receiver
            offset_data = Protocol.recv_all(s, 8)
            if not offset_data:
                print("Error: Did not receive offset from receiver.")
                return
                
            offset = struct.unpack('!Q', offset_data)[0]
            
            if offset > 0:
                print(f"[*] Resuming upload from byte {offset}...")
            
            if offset >= filesize:
                 print("[*] Receiver already has the file.")
                 if self.callback: self.callback(100)
                 return

            # Chunked Encrypted Transfer
            sent_bytes = offset
            with open(filepath, 'rb') as f:
                if offset > 0:
                    f.seek(offset)
                    
                while True:
                    chunk = f.read(Protocol.CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    encrypted_chunk = self.cipher.encrypt(chunk)
                    # Send [Length] [Encrypted Chunk]
                    s.sendall(struct.pack('!I', len(encrypted_chunk)))
                    s.sendall(encrypted_chunk)
                    
                    sent_bytes += len(chunk)
                    
                    # Progress Callback
                    if self.callback:
                        percent = (sent_bytes / filesize) * 100
                        self.callback(percent)
            
            print(f"\n[DONE] Sent {filename}")

# --- API for App ---

def send_file_logic(ip, file_path, key_str, progress_callback=None):
    """
    Refactor your sending code into this function.
    Returns specific strings that the App can display as status.
    """
    try:
        if not os.path.exists(file_path):
            return "Error: File not found"

        # Ensure key is bytes
        if isinstance(key_str, str):
            key = key_str.encode()
        else:
            key = key_str

        # Validate IP format roughly
        if not ip:
            return "Error: IP required"

        sender = Sender(target_ip=ip, key=key, callback=progress_callback)
        # We need to capture the output or error status
        sender.send_file(file_path)
        return "Success: File sent!"
    except Exception as e:
        import traceback
        traceback.print_exc()
        return f"Error: {str(e)}"

def discover_receivers(timeout=3):
    """
    Listens for UDP beacons from Receivers.
    Returns the IP of the first one found, or None.
    """
    UDP_PORT = 9998
    KEYWORD = b"NAPSTER_V2"
    
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # Not needed for listening
        s.settimeout(timeout)
        try:
            s.bind(('', UDP_PORT))
            print(f"[*] Scanning for receivers on port {UDP_PORT}...")
            
            start = time.time()
            while time.time() - start < timeout:
                try:
                    data, addr = s.recvfrom(1024)
                    if data == KEYWORD:
                        return addr[0]
                except socket.timeout:
                    break
        except Exception as e:
            print(f"Discovery error: {e}")
            return None
    return None

class Broadcaster:
    def __init__(self, interval=3):
        self.interval = interval
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._broadcast_loop)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.running = False

    def _broadcast_loop(self):
        UDP_PORT = 9998
        MESSAGE = b"NAPSTER_V2"
        
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            # s.bind(('', 0)) # Bind to ephemeral port
            
            while self.running:
                try:
                    s.sendto(MESSAGE, ('255.255.255.255', UDP_PORT))
                    # Also broadcast to local broadcast address just in case
                    # s.sendto(MESSAGE, ('<broadcast>', UDP_PORT)) 
                except Exception as e:
                    # Ignore network errors (e.g. network down)
                    pass
                time.sleep(self.interval)

# --- Watcher ---

class Watcher:
    def __init__(self, folder, sender):
        self.folder = folder
        self.sender = sender
        self.observer = Observer()

    def run(self):
        event_handler = Handler(self.sender)
        self.observer.schedule(event_handler, self.folder, recursive=False)
        self.observer.start()
        print(f"[*] Watching folder: {self.folder}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()

class Handler(FileSystemEventHandler):
    def __init__(self, sender):
        self.sender = sender

    def on_created(self, event):
        if not event.is_directory:
            # Debounce/wait for file write to finish
            file_size = -1
            while file_size != os.path.getsize(event.src_path):
                file_size = os.path.getsize(event.src_path)
                time.sleep(0.5)
            
            print(f"\n[New File Detected] {event.src_path}")
            self.sender.send_file(event.src_path)

# --- Main ---

def get_key(args):
    """Retrieve key from args or file, or generate one."""
    if args.key:
        return args.key.encode()
    # For now, we will require the user to copy-paste the key or use a default one for this demo
    # In a real scenario, we might read from a config file.
    # AUTO-GENERATE if not provided? No, receiver needs it.
    # DEFAULT for ease of use?
    DEFAULT_KEY = b'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY=' # Base64 encoded 32 bytes
    # But Fernet keys must be valid.
    # Let's generate a valid one if none provided, but then receiver will fail if they don't match.
    # STRATEGY: 
    # If starting Receiver without key -> Generate and Print.
    # If starting Sender without key -> Ask user to input, OR use arg.
    
    # Simple strategy for this "mini-internet":
    # If env var NAPSTER_KEY is set, use it.
    # Else if --key, use it.
    # Else, use a hardcoded default for testing (NOT SECURE but EASY).
    # Correct way: Fernet.generate_key()
    
    # We will use a fixed key for this demo unless specified, to avoid copy-paste hassle on mobile.
    # A valid Fernet key.
    HARDCODED_KEY = b'C-z54yZl8W_d8z54yZl8W_d8z54yZl8W_d8z54yZl8W=' # valid url-safe base64? Probably not.
    # Let's clear the key requirement and ask user to use --key or we generate one.
    
    if os.environ.get('NAPSTER_KEY'):
        return os.environ.get('NAPSTER_KEY').encode()
        
    # Generate a temporary key file?
    key_path = '.napster_key'
    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            return f.read().strip()
            
    # If no key, generate and save
    key = Fernet.generate_key()
    with open(key_path, 'wb') as f:
        f.write(key)
    print(f"[!] No key found. Generated new key: {key.decode()}")
    print(f"[!] Save this key! You need it on the other device.")
    return key

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Napster P2P V2 (Encrypted)")
    # Global key not needed if added to each, but keeps it flexible? No, remove global to avoid confusion.
    
    subparsers = parser.add_subparsers(dest='mode', required=True)

    # Receiver
    parser_recv = subparsers.add_parser('receive')
    parser_recv.add_argument('--out', default='./received_files', help='Output folder')
    parser_recv.add_argument('--port', type=int, default=9999)
    parser_recv.add_argument('--key', help='Encryption key')

    # Sender
    parser_send = subparsers.add_parser('send')
    parser_send.add_argument('--ip', required=True, help='Receiver IP')
    parser_send.add_argument('--file', required=True, help='File to send')
    parser_send.add_argument('--port', type=int, default=9999)
    parser_send.add_argument('--key', help='Encryption key')

    # Watcher
    parser_watch = subparsers.add_parser('watch')
    parser_watch.add_argument('--folder', required=True, help='Folder to watch')
    parser_watch.add_argument('--ip', required=True, help='Receiver IP')
    parser_watch.add_argument('--port', type=int, default=9999)
    parser_watch.add_argument('--key', help='Encryption key')

    args = parser.parse_args()

    # Load Key
    # We need the key to init sender/receiver.
    # If user provides key via CLI, use it.
    # If not, try to load from file or generate.
    if args.key:
        fernet_key = args.key.encode()
    else:
        # Check if key file exists
        if os.path.exists('napster.key'):
            with open('napster.key', 'rb') as f:
                fernet_key = f.read().strip()
        else:
            if args.mode == 'receive':
                fernet_key = Fernet.generate_key()
                with open('napster.key', 'wb') as f:
                    f.write(fernet_key)
                print(f"\n[KEY GENERATED] {fernet_key.decode()}")
                print("Use this key on the sender:")
                print(f"python3 napster.py send --key {fernet_key.decode()} ...")
            else:
                print("Error: You must provide a --key (or put it in napster.key) to send.")
                sys.exit(1)

    print(f"[*] Using Key: {fernet_key.decode()[:10]}...")

    if args.mode == 'receive':
        Receiver(port=args.port, output_dir=args.out, key=fernet_key).start()
    elif args.mode == 'send':
        Sender(target_ip=args.ip, target_port=args.port, key=fernet_key).send_file(args.file)
    elif args.mode == 'watch':
        sender = Sender(target_ip=args.ip, target_port=args.port, key=fernet_key)
        Watcher(args.folder, sender).run()
