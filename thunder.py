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

# Constants for the application
APP_DATA_DIR = os.path.join(os.path.expanduser("~"), ".thundertransfer")
HISTORY_FILE = os.path.join(APP_DATA_DIR, "transfer_history.json")
CHUNK_SIZE = 8192  # 8KB chunks for transfer

class TransferStats:
    def __init__(self, total_size):
        self.total_size = total_size
        self.transferred = 0
        self.start_time = time.time()
        self.last_update = self.start_time
        self.last_transferred = 0
        self.current_speed = 0  # bytes per second
        
    def update(self, additional_bytes):
        current_time = time.time()
        self.transferred += additional_bytes
        
        # Update speed calculation every second
        time_diff = current_time - self.last_update
        if time_diff >= 1.0:
            bytes_since_last = self.transferred - self.last_transferred
            self.current_speed = bytes_since_last / time_diff
            self.last_update = current_time
            self.last_transferred = self.transferred
            
    def get_progress(self):
        return (self.transferred / self.total_size) if self.total_size > 0 else 0
        
    def get_eta(self):
        if self.current_speed > 0:
            remaining_bytes = self.total_size - self.transferred
            return remaining_bytes / self.current_speed
        return 0
        
    def get_speed_str(self):
        return humanize.naturalsize(self.current_speed, binary=True) + "/s"
        
    def get_progress_str(self):
        return f"{humanize.naturalsize(self.transferred, binary=True)} / {humanize.naturalsize(self.total_size, binary=True)}"
        
    def get_eta_str(self):
        eta = self.get_eta()
        if eta <= 0:
            return "calculating..."
        return humanize.naturaltime(-eta, future=True)

# =============================================================================
# PART 1: Driver Check and Auto-Installation
# =============================================================================
def check_and_install_thunderbolt_driver():
    """
    Checks if the Thunderbolt driver is installed.
    If not found, guides the user to install it using Lenovo System Update.
    """
    try:
        # Run driverquery to list drivers in CSV format
        output = subprocess.check_output(["driverquery", "/FO", "CSV"], text=True)
        if "Thunderbolt" in output:
            print("Thunderbolt driver is installed.")
            return True
        else:
            print("Thunderbolt driver not found.")
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
                "After installation, please restart this application."
            )
            return False
    except Exception as e:
        print("Error checking Thunderbolt driver:", e)
        messagebox.showerror("Error", f"Failed to check Thunderbolt driver status: {str(e)}")
        return False

# =============================================================================
# PART 2: File Transfer Server (to be run on the receiving machine)
# =============================================================================
class FileTransferServer(threading.Thread):
    """
    A simple TCP server that listens for incoming file transfers.
    The protocol:
      - Receive 4 bytes indicating header length.
      - Receive JSON header with:
          target_dir, is_folder, items.
      - Receive the file content and save it under target_dir.
    """
    def __init__(self, host='', port=5001):
        super().__init__()
        self.host = host
        self.port = port
        self.server_socket = None
        self.is_running = False

    def run(self):
        self.is_running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print("FileTransferServer listening on port", self.port)
        while self.is_running:
            try:
                client_socket, addr = self.server_socket.accept()
                print("Accepted connection from", addr)
                threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()
            except Exception as e:
                print("Server error:", e)
        self.server_socket.close()

    def handle_client(self, client_socket):
        try:
            # Receive header length (first 4 bytes, big-endian)
            header_length_bytes = client_socket.recv(4)
            if not header_length_bytes:
                return
            header_length = int.from_bytes(header_length_bytes, byteorder='big')
            
            # Now receive the JSON header
            header_data = client_socket.recv(header_length).decode()
            header = json.loads(header_data)
            target_dir = header.get("target_dir")
            is_folder = header.get("is_folder", False)
            items = header.get("items", [])
            
            # Create base target directory if it doesn't exist
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)

            for item in items:
                rel_path = item["rel_path"]
                size = item["size"]
                is_dir = item["is_dir"]
                
                full_path = os.path.join(target_dir, rel_path)
                
                if is_dir:
                    os.makedirs(full_path, exist_ok=True)
                    continue
                
                # Ensure the parent directory exists
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                
                # Receive and save the file
                with open(full_path, 'wb') as f:
                    remaining = size
                    while remaining > 0:
                        chunk_size = min(remaining, CHUNK_SIZE)
                        chunk = client_socket.recv(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        remaining -= len(chunk)
                print(f"Saved: {full_path}")
                
        except Exception as e:
            print("Error handling client:", e)
        finally:
            client_socket.close()

    def stop(self):
        self.is_running = False
        # Create a dummy connection to unblock accept()
        try:
            dummy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dummy.connect((self.host, self.port))
            dummy.close()
        except Exception:
            pass

# =============================================================================
# PART 3: File Transfer Client Function
# =============================================================================
def send_file(target_ip, target_port, path, target_dir, progress_callback=None):
    try:
        # Connect to the server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((target_ip, target_port))

        # Prepare the file list and metadata
        items = []
        files_to_send = []
        total_size = 0
        
        if os.path.isfile(path):
            # Single file
            size = os.path.getsize(path)
            total_size = size
            rel_path = os.path.basename(path)
            items.append({"rel_path": rel_path, "size": size, "is_dir": False})
            files_to_send.append((path, rel_path, size))
        else:
            # Directory
            base_path = os.path.dirname(path)
            for root, dirs, files in os.walk(path):
                # Add directories
                for dir_name in dirs:
                    full_dir_path = os.path.join(root, dir_name)
                    rel_path = os.path.relpath(full_dir_path, base_path)
                    items.append({"rel_path": rel_path, "size": 0, "is_dir": True})
                
                # Add files
                for file_name in files:
                    full_file_path = os.path.join(root, file_name)
                    rel_path = os.path.relpath(full_file_path, base_path)
                    size = os.path.getsize(full_file_path)
                    total_size += size
                    items.append({"rel_path": rel_path, "size": size, "is_dir": False})
                    files_to_send.append((full_file_path, rel_path, size))

        # Initialize transfer stats
        stats = TransferStats(total_size)
        if progress_callback:
            progress_callback(stats)

        # Prepare and send header
        header = {
            "target_dir": target_dir,
            "is_folder": os.path.isdir(path),
            "items": items
        }
        header_json = json.dumps(header)
        header_bytes = header_json.encode()
        
        # Send header length first (4 bytes, big-endian)
        client_socket.send(len(header_bytes).to_bytes(4, byteorder='big'))
        # Send the header itself
        client_socket.send(header_bytes)

        # Send all files
        for full_path, rel_path, size in files_to_send:
            with open(full_path, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    client_socket.send(chunk)
                    stats.update(len(chunk))
                    if progress_callback:
                        progress_callback(stats)
            print(f"Sent: {rel_path}")

    except Exception as e:
        raise Exception(f"Failed to send file: {str(e)}")
    finally:
        client_socket.close()

# =============================================================================
# PART 4: GUI Application (Tkinter based)
# =============================================================================
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
        progress = stats.get_progress() * 100
        self.progress_var.set(progress)
        
        # Update progress text
        self.progress_label.config(
            text=f"{progress:.1f}% ({stats.get_progress_str()})")
        
        # Update speed and ETA
        self.speed_label.config(
            text=f"{stats.get_speed_str()} - {stats.get_eta_str()}")
        
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
        
        try:
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
            
        except Exception as e:
            messagebox.showerror("Error", f"Transfer failed: {str(e)}")
            self.status_label.config(text="Status: Transfer failed!")
            self.hide_progress()

    def on_closing(self):
        """Handle window closing event"""
        if hasattr(self, 'server') and self.server:
            self.server.stop()
        self.master.quit()
        self.master.destroy()

# =============================================================================
# PART 5: Main Execution
# =============================================================================
if __name__ == "__main__":
    # Step 1: Check (and auto-install if needed) the Thunderbolt driver.
    if not check_and_install_thunderbolt_driver():
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
