import os
import json
import socket
import threading
import subprocess
import requests
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox, ttk
import sys
from datetime import datetime
import time
import humanize
import hashlib
from pathlib import Path

# Constants for the application
APP_DATA_DIR = os.path.join(os.path.expanduser("~"), ".thundertransfer")
HISTORY_FILE = os.path.join(APP_DATA_DIR, "transfer_history.json")
TRANSFERS_FILE = os.path.join(APP_DATA_DIR, "transfers.json")
CHUNK_SIZE = 8192  # 8KB chunks for transfer
MAX_RETRIES = 10
RETRY_DELAY = 2  # seconds between retries

class TransferStats:
    def __init__(self, total_size, resumed_size=0):
        self.total_size = total_size
        self.transferred = resumed_size
        self.start_time = time.time()
        self.last_update = self.start_time
        self.last_transferred = resumed_size
        self.current_speed = 0
        self.retries = 0
        
    def increment_retries(self):
        self.retries += 1
        return self.retries <= MAX_RETRIES
        
    def reset_speed(self):
        self.last_update = time.time()
        self.last_transferred = self.transferred

class TransferRecord:
    """Class to manage transfer records and resumption"""
    def __init__(self):
        self.records = self.load_records()
        
    def load_records(self):
        """Load transfer records from file"""
        try:
            if os.path.exists(TRANSFERS_FILE):
                with open(TRANSFERS_FILE, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            print(f"Error loading transfer records: {e}")
            return {}
            
    def save_records(self):
        """Save transfer records to file"""
        try:
            os.makedirs(os.path.dirname(TRANSFERS_FILE), exist_ok=True)
            with open(TRANSFERS_FILE, 'w') as f:
                json.dump(self.records, f)
        except Exception as e:
            print(f"Error saving transfer records: {e}")
            
    def get_record_key(self, target_ip, target_dir, file_path):
        """Generate a unique key for a transfer record"""
        file_hash = self.get_file_hash(file_path)
        return f"{target_ip}:{target_dir}:{file_hash}"
        
    def get_file_hash(self, file_path):
        """Calculate SHA-256 hash of first and last 1MB of file for quick comparison"""
        try:
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                # Read first 1MB
                start_chunk = f.read(1024 * 1024)
                sha256.update(start_chunk)
                
                # Read last 1MB
                f.seek(-min(1024 * 1024, os.path.getsize(file_path)), 2)
                end_chunk = f.read()
                sha256.update(end_chunk)
                
            return sha256.hexdigest()
        except Exception as e:
            print(f"Error calculating file hash: {e}")
            return None
            
    def get_transfer_progress(self, target_ip, target_dir, file_path):
        """Get the progress of a previous transfer"""
        key = self.get_record_key(target_ip, target_dir, file_path)
        return self.records.get(key, {}).get('bytes_transferred', 0)
        
    def update_transfer_progress(self, target_ip, target_dir, file_path, bytes_transferred):
        """Update the progress of a transfer"""
        key = self.get_record_key(target_ip, target_dir, file_path)
        self.records[key] = {
            'bytes_transferred': bytes_transferred,
            'last_updated': time.time(),
            'file_size': os.path.getsize(file_path)
        }
        self.save_records()
        
    def clear_transfer_record(self, target_ip, target_dir, file_path):
        """Clear the record of a completed transfer"""
        key = self.get_record_key(target_ip, target_dir, file_path)
        if key in self.records:
            del self.records[key]
            self.save_records()

def send_file(target_ip, target_port, path, target_dir, progress_callback=None):
    """Send a file or directory to the target computer"""
    transfer_record = TransferRecord()
    client_socket = None
    try:
        # Get the base directory for relative paths
        base_dir = os.path.dirname(path) if os.path.isfile(path) else path
        files_to_send = []
        
        # Collect all files to send
        if os.path.isfile(path):
            files_to_send.append((path, os.path.basename(path)))
        else:
            for root, _, files in os.walk(path):
                for file in files:
                    abs_path = os.path.join(root, file)
                    rel_path = os.path.relpath(abs_path, base_dir)
                    files_to_send.append((abs_path, rel_path))
        
        total_size = sum(os.path.getsize(f[0]) for f in files_to_send)
        stats = TransferStats(total_size)
        
        for file_path, rel_path in files_to_send:
            size = os.path.getsize(file_path)
            remote_path = os.path.join(target_dir, rel_path).replace('\\', '/')
            
            # Check local transfer record
            resume_position = transfer_record.get_transfer_progress(target_ip, target_dir, file_path)
            if resume_position >= size:
                print(f"File already transferred: {rel_path}")
                stats.transferred += size
                if progress_callback:
                    progress_callback(stats)
                continue
            
            # Attempt to connect with retries
            for attempt in range(MAX_RETRIES):
                try:
                    if client_socket:
                        client_socket.close()
                    
                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client_socket.connect((target_ip, target_port))
                    
                    # Send file info with resume position
                    file_info = f"{rel_path}|{size}|{resume_position}"
                    client_socket.sendall(file_info.encode())
                    
                    # Wait for acknowledgment
                    response = client_socket.recv(1024).decode()
                    if response != "OK":
                        raise Exception(f"Server response: {response}")
                    
                    # Open file and seek to resume position
                    with open(file_path, 'rb') as f:
                        f.seek(resume_position)
                        bytes_sent = resume_position
                        
                        while bytes_sent < size:
                            chunk = f.read(CHUNK_SIZE)
                            if not chunk:
                                break
                            client_socket.send(chunk)
                            bytes_sent += len(chunk)
                            stats.transferred += len(chunk)
                            
                            # Update transfer record periodically
                            if bytes_sent % (CHUNK_SIZE * 100) == 0:  # Every ~800KB
                                transfer_record.update_transfer_progress(
                                    target_ip, target_dir, file_path, bytes_sent)
                            
                            if progress_callback:
                                progress_callback(stats)
                                
                    # Clear transfer record on successful completion
                    transfer_record.clear_transfer_record(target_ip, target_dir, file_path)
                    print(f"Sent: {rel_path}")
                    break
                    
                except Exception as e:
                    print(f"Error sending file (attempt {attempt + 1}): {e}")
                    stats.increment_retries()
                    if progress_callback:
                        progress_callback(stats)
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_DELAY)
                    else:
                        raise
                        
    except Exception as e:
        print(f"Error during transfer: {e}")
        raise
    finally:
        if client_socket:
            client_socket.close()

class FileTransferServer(threading.Thread):
    """A server thread that listens for incoming file transfers"""
    def __init__(self, port=5001):
        super().__init__()
        self.port = port
        self._stop_event = threading.Event()
        
    def run(self):
        """Start the server and listen for incoming connections"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(('0.0.0.0', self.port))
                server_socket.listen(5)
                server_socket.settimeout(1)  # 1 second timeout for checking stop event
                
                print(f"Server listening on port {self.port}")
                
                while not self._stop_event.is_set():
                    try:
                        client_socket, address = server_socket.accept()
                        print(f"Connection from {address}")
                        
                        # Handle the connection in a new thread
                        client_thread = threading.Thread(
                            target=self.handle_client,
                            args=(client_socket, address),
                            daemon=True
                        )
                        client_thread.start()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        print(f"Error accepting connection: {e}")
                        
        except Exception as e:
            print(f"Server error: {e}")
            
    def handle_client(self, client_socket, address):
        """Handle an incoming file transfer from a client"""
        try:
            with client_socket:
                # Receive the file info
                file_info = client_socket.recv(1024).decode()
                rel_path, size, resume_position = file_info.split('|')
                size = int(size)
                resume_position = int(resume_position)
                
                # Send acknowledgment
                client_socket.sendall(b"OK")
                
                # Create the downloads directory if it doesn't exist
                downloads_dir = os.path.join(os.path.expanduser("~"), "Downloads")
                os.makedirs(downloads_dir, exist_ok=True)
                
                # Prepare the file path
                file_path = os.path.join(downloads_dir, os.path.basename(rel_path))
                
                # Receive the file
                with open(file_path, 'wb') as f:
                    received = 0
                    if resume_position > 0:
                        f.seek(resume_position)
                    while received < size:
                        data = client_socket.recv(CHUNK_SIZE)
                        if not data:
                            break
                        f.write(data)
                        received += len(data)
                        
                print(f"File {rel_path} received successfully")
                
        except Exception as e:
            print(f"Error handling client {address}: {e}")
            
    def stop(self):
        """Stop the server"""
        self._stop_event.set()

class FileTransferApp:
    def __init__(self, master):
        self.master = master
        master.title("ThunderTransfer")
        
        # Configure window
        master.geometry("800x600")
        master.configure(bg='#f0f0f0')
        
        # Set up window close handler
        master.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Initialize history
        self.load_history()
        
        # Create main container with padding
        main_container = tk.Frame(master, bg='#f0f0f0')
        main_container.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        
        # Style configuration
        title_style = {'bg': '#f0f0f0', 'fg': '#333333', 'font': ('Helvetica', 16, 'bold')}
        label_style = {'bg': '#f0f0f0', 'fg': '#333333', 'font': ('Helvetica', 10)}
        button_style = {'bg': '#2196F3', 'fg': 'white', 'font': ('Helvetica', 10, 'bold'),
                       'relief': tk.FLAT, 'padx': 15, 'pady': 8}
        
        # Title
        title_label = tk.Label(main_container, text="ThunderTransfer", **title_style)
        title_label.pack(pady=(0, 20))
        
        # Connection Frame
        conn_frame = tk.LabelFrame(main_container, text="Connection Settings", bg='#f0f0f0', fg='#333333')
        conn_frame.pack(fill=tk.X, pady=(0, 15))
        
        # IP Frame
        ip_frame = tk.Frame(conn_frame, bg='#f0f0f0')
        ip_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(ip_frame, text="Local TB IP:", **label_style).pack(side=tk.LEFT, padx=(0, 5))
        self.local_ip_value = tk.Label(ip_frame, text="Detecting...", **label_style)
        self.local_ip_value.pack(side=tk.LEFT, padx=5)
        
        tk.Button(ip_frame, text="Refresh", command=self.refresh_local_ip,
                 **button_style).pack(side=tk.LEFT, padx=5)
        tk.Button(ip_frame, text="Update IP", command=self.update_ip,
                 **button_style).pack(side=tk.LEFT, padx=5)
        
        # Target IP Frame
        target_frame = tk.Frame(conn_frame, bg='#f0f0f0')
        target_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(target_frame, text="Target IP:", **label_style).pack(side=tk.LEFT, padx=(0, 5))
        
        # Combobox for target IP selection
        self.ip_var = tk.StringVar()
        self.ip_combo = ttk.Combobox(target_frame, textvariable=self.ip_var, font=('Helvetica', 10))
        self.ip_combo.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        self.ip_combo.insert(0, "169.254.")
        self.update_ip_list()
        self.ip_combo.bind('<<ComboboxSelected>>', self.on_ip_selected)
        
        tk.Label(target_frame, text="Port:", **label_style).pack(side=tk.LEFT, padx=(10, 5))
        self.port_entry = tk.Entry(target_frame, width=6, font=('Helvetica', 10))
        self.port_entry.pack(side=tk.LEFT, padx=5)
        self.port_entry.insert(0, "5001")
        
        tk.Button(target_frame, text="Test Connection", command=self.test_connection,
                 **button_style).pack(side=tk.LEFT, padx=5)
        
        # Transfer Frame
        transfer_frame = tk.LabelFrame(main_container, text="Transfer", bg='#f0f0f0', fg='#333333')
        transfer_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Destination frame
        dest_frame = tk.Frame(transfer_frame, bg='#f0f0f0')
        dest_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(dest_frame, text="Destination:", **label_style).pack(side=tk.LEFT, padx=(0, 5))
        
        # Combobox for destination selection
        self.dest_var = tk.StringVar()
        self.dest_combo = ttk.Combobox(dest_frame, textvariable=self.dest_var, font=('Helvetica', 10))
        self.dest_combo.pack(side=tk.LEFT, expand=True, fill=tk.X)
        
        # Add new destination button
        tk.Button(dest_frame, text="New", command=self.add_destination,
                 **button_style).pack(side=tk.LEFT, padx=5)
        
        # Selection info
        self.selection_label = tk.Label(transfer_frame, text="No file/folder selected", 
                                     **label_style, wraplength=700)
        self.selection_label.pack(pady=10, padx=10)
        
        # Buttons frame
        buttons_frame = tk.Frame(transfer_frame, bg='#f0f0f0')
        buttons_frame.pack(pady=10)
        
        select_button = tk.Button(buttons_frame, text="Select File/Folder", 
                               command=self.select_file, **button_style)
        select_button.pack(side=tk.LEFT, padx=5)
        
        self.transfer_button = tk.Button(buttons_frame, text="Transfer", 
                                      command=self.transfer_file, **button_style)
        self.transfer_button.pack(side=tk.LEFT, padx=5)
        
        # Progress Frame
        self.progress_frame = tk.Frame(transfer_frame, bg='#f0f0f0')
        self.progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.progress_frame, 
                                         variable=self.progress_var,
                                         maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(5, 0))
        
        # Progress labels frame
        self.progress_labels_frame = tk.Frame(self.progress_frame, bg='#f0f0f0')
        self.progress_labels_frame.pack(fill=tk.X, pady=(5, 0))
        
        # Progress details (left side)
        self.progress_label = tk.Label(self.progress_labels_frame, 
                                    text="", 
                                    bg='#f0f0f0', 
                                    font=('Helvetica', 9))
        self.progress_label.pack(side=tk.LEFT)
        
        # Speed and ETA (right side)
        self.speed_label = tk.Label(self.progress_labels_frame, 
                                 text="", 
                                 bg='#f0f0f0', 
                                 font=('Helvetica', 9))
        self.speed_label.pack(side=tk.RIGHT)
        
        # Initially hide progress elements
        self.hide_progress()
        
        # Status
        self.status_label = tk.Label(main_container, text="Status: Ready", **label_style)
        self.status_label.pack(pady=5)
        
        self.selected_file = None
        self.refresh_local_ip()

    def load_history(self):
        """Load transfer history from file"""
        # Create app data directory if it doesn't exist
        os.makedirs(APP_DATA_DIR, exist_ok=True)
        
        try:
            if os.path.exists(HISTORY_FILE):
                with open(HISTORY_FILE, 'r') as f:
                    self.history = json.load(f)
            else:
                self.history = {}
        except Exception as e:
            print(f"Error loading history: {e}")
            self.history = {}

    def save_history(self):
        """Save transfer history to file"""
        try:
            with open(HISTORY_FILE, 'w') as f:
                json.dump(self.history, f, indent=2)
        except Exception as e:
            print(f"Error saving history: {e}")

    def update_ip_list(self):
        """Update the IP combobox with saved IPs"""
        ips = list(self.history.keys())
        if not ips:
            ips = ["169.254."]
        self.ip_combo['values'] = ips
        
    def update_destinations(self):
        """Update the destinations combobox based on selected IP"""
        ip = self.ip_var.get()
        if ip in self.history:
            destinations = [item['path'] for item in self.history[ip]]
            self.dest_combo['values'] = destinations
            if destinations:
                self.dest_combo.set(destinations[0])
        else:
            self.dest_combo['values'] = []
            self.dest_combo.set('')

    def on_ip_selected(self, event=None):
        """Handle IP selection change"""
        self.update_destinations()

    def add_destination(self):
        """Add a new destination for the current IP"""
        dest = simpledialog.askstring("New Destination", 
                                    "Enter the destination path on the target machine:")
        if dest:
            ip = self.ip_var.get()
            if ip not in self.history:
                self.history[ip] = []
            
            # Check if destination already exists
            if not any(item['path'] == dest for item in self.history[ip]):
                self.history[ip].append({
                    'path': dest,
                    'last_used': datetime.now().isoformat()
                })
                self.save_history()
                self.update_destinations()
                self.dest_combo.set(dest)

    def update_destination_usage(self, ip, dest):
        """Update the last used timestamp for a destination"""
        if ip in self.history:
            for item in self.history[ip]:
                if item['path'] == dest:
                    item['last_used'] = datetime.now().isoformat()
                    break
            self.save_history()

    def refresh_local_ip(self):
        """Refresh the displayed local Thunderbolt IP address"""
        ip = get_thunderbolt_ip()
        if ip:
            self.local_ip_value.config(text=ip)
        else:
            self.local_ip_value.config(text="Not detected")
            
    def update_ip(self):
        """Allow user to manually update the Thunderbolt IP address"""
        current_ip = self.local_ip_value.cget("text")
        if current_ip == "Not detected":
            current_ip = "169.254."
            
        new_ip = simpledialog.askstring("Update IP", 
                                      "Enter new Thunderbolt IP address:",
                                      initialvalue=current_ip)
        if new_ip:
            if new_ip.startswith("169.254."):
                try:
                    # Attempt to validate IP format
                    socket.inet_aton(new_ip)
                    # Use netsh to set the IP address (requires admin privileges)
                    cmd = f'netsh interface ip set address "Thunderbolt" static {new_ip} 255.255.0.0'
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    if result.returncode == 0:
                        self.local_ip_value.config(text=new_ip)
                        messagebox.showinfo("Success", "IP address updated successfully")
                    else:
                        messagebox.showerror("Error", 
                            "Failed to update IP address. Make sure you have administrator privileges.")
                except Exception as e:
                    messagebox.showerror("Error", f"Invalid IP address format: {str(e)}")
            else:
                messagebox.showerror("Error", 
                    "IP address must start with '169.254.' for Thunderbolt network")

    def test_connection(self):
        """Test the connection to the target computer."""
        target_ip = self.ip_var.get().strip()
        target_port = int(self.port_entry.get().strip())

        try:
            # Try to create a test connection
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)  # 2 second timeout
                s.connect((target_ip, target_port))
                self.status_label.config(text="Status: Connected successfully!", fg="green")
                messagebox.showinfo("Success", f"Successfully connected to {target_ip}:{target_port}")
        except Exception as e:
            self.status_label.config(text=f"Status: Connection failed - {str(e)}", fg="red")
            messagebox.showerror("Connection Error", 
                f"Could not connect to {target_ip}:{target_port}\n\n"
                "Please check:\n"
                "1. Target computer is running this application\n"
                "2. Thunderbolt connection is established\n"
                "3. IP address is correct (should start with 169.254.)\n"
                "4. Port number matches the server")

    def select_file(self):
        path = filedialog.askdirectory() or filedialog.askopenfilename()
        if path:
            self.selected_file = path
            if os.path.isdir(path):
                num_files = sum([len(files) for _, _, files in os.walk(path)])
                self.selection_label.config(text=f"Selected folder: {path}\nContains {num_files} files")
            else:
                size = os.path.getsize(path)
                size_str = f"{size/1024/1024:.1f} MB" if size > 1024*1024 else f"{size/1024:.1f} KB"
                self.selection_label.config(text=f"Selected file: {path}\nSize: {size_str}")

    def hide_progress(self):
        """Hide progress bar and labels"""
        self.progress_bar.pack_forget()
        self.progress_labels_frame.pack_forget()
        self.progress_var.set(0)
        self.progress_label.config(text="")
        self.speed_label.config(text="")
        
    def show_progress(self):
        """Show progress bar and labels"""
        self.progress_bar.pack(fill=tk.X, pady=(5, 0))
        self.progress_labels_frame.pack(fill=tk.X, pady=(5, 0))
        
    def update_progress(self, stats):
        """Update progress bar and labels with transfer statistics"""
        progress = stats.transferred / stats.total_size * 100
        self.progress_var.set(progress)
        
        # Update progress text
        self.progress_label.config(
            text=f"{progress:.1f}% ({stats.transferred / stats.total_size * 100:.1f}%)")
        
        # Update speed and ETA
        retry_text = f" - Retry {stats.retries}/{MAX_RETRIES}" if stats.retries > 0 else ""
        self.speed_label.config(
            text=f"{stats.transferred / (time.time() - stats.start_time) / 1024:.1f} KB/s - {stats.transferred / stats.total_size * 100:.1f}%{retry_text}")
        
        # Update the window to ensure progress is shown
        self.master.update()

    def transfer_file(self):
        """Initiates the file transfer after ensuring a file and connection details are valid."""
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a file or folder first.")
            return
        
        target_ip = self.ip_var.get()
        if not target_ip:
            messagebox.showerror("Error", "Please enter a target IP address.")
            return
            
        try:
            target_port = int(self.port_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid port number.")
            return
            
        dest_dir = self.dest_var.get()
        if not dest_dir:
            messagebox.showerror("Error", "Please select or enter a destination directory.")
            return
        
        # Update history
        if target_ip not in self.history:
            self.history[target_ip] = []
        self.update_destination_usage(target_ip, dest_dir)
        
        # Clear previous status and show progress
        self.status_label.config(text="Status: Starting transfer...")
        self.show_progress()
        
        # Start transfer in a separate thread
        def transfer_thread():
            try:
                send_file(target_ip, target_port, self.selected_file, dest_dir,
                         progress_callback=self.update_progress)
                self.master.after(0, lambda: self.status_label.config(
                    text="Status: Transfer completed successfully!"))
            except Exception as e:
                self.master.after(0, lambda: self.status_label.config(
                    text=f"Status: Transfer failed! {str(e)}"))
            finally:
                self.master.after(2000, self.hide_progress)
        
        threading.Thread(target=transfer_thread, daemon=True).start()
        
    def on_closing(self):
        """Handle window closing event"""
        if hasattr(self, 'server') and self.server:
            self.server.stop()
        self.master.quit()
        self.master.destroy()

def get_thunderbolt_ip():
    """Get the IP address of the Thunderbolt network interface"""
    try:
        # Look for interfaces with the Thunderbolt IP prefix (169.254)
        for iface in socket.if_nameindex():
            addrs = socket.getaddrinfo(socket.gethostname(), None)
            for addr in addrs:
                ip = addr[4][0]
                if ip.startswith('169.254.'):
                    return ip
        return None
    except Exception as e:
        print(f"Error getting Thunderbolt IP: {e}")
        return None

if __name__ == "__main__":
    # Step 1: Check (and auto-install if needed) the Thunderbolt driver.
    try:
        import subprocess
        output = subprocess.check_output(["driverquery", "/FO", "CSV"], text=True)
        thunderbolt_drivers = [
            "Thunderbolt(TM)",
            "Intel(R) Thunderbolt(TM)",
            "ThunderboltService",
            "Thunderbolt Controller"
        ]
        if not any(driver in output for driver in thunderbolt_drivers):
            messagebox.showinfo("Driver Installation Required", 
                "Thunderbolt driver is not installed. Please install it using one of these methods:\n\n"
                "1. Recommended: Use Lenovo System Update\n"
                "   - Download from: support.lenovo.com/solutions/ht003029\n"
                "   - Run System Update\n"
                "   - Install 'Intel Thunderbolt Driver'\n\n"
                "2. Manual Installation:\n"
                "   - Visit support.lenovo.com\n"
                "   - Enter your machine type\n"
                "   - Go to Drivers & Software\n"
                "   - Find and install 'Intel Thunderbolt Driver'\n\n"
                "After installation, please restart this application.")
            sys.exit(1)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to check Thunderbolt driver: {str(e)}")
        sys.exit(1)
        
    root = tk.Tk()
    app = FileTransferApp(root)
    
    # Start the file transfer server in a daemon thread
    app.server = FileTransferServer()
    app.server.daemon = True  # Make sure the thread stops when the main program exits
    app.server.start()
    
    # Schedule the initial IP refresh
    root.after(100, app.refresh_local_ip)
    
    root.mainloop()
