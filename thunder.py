import os
import json
import socket
import threading
import subprocess
import requests
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox

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
          target_dir, file_name, file_size.
      - Receive the file content and save it under target_dir.
    """
    def __init__(self, host='', port=5001):
        super().__init__()
        self.host = host  # Bind to all interfaces by default
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
            file_name = header.get("file_name")
            file_size = header.get("file_size")
            print(f"Incoming file: {file_name} ({file_size} bytes) to be saved in {target_dir}")
            
            # Ensure the target directory exists
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)
            file_path = os.path.join(target_dir, file_name)
            
            # Receive the file data
            with open(file_path, 'wb') as f:
                remaining = file_size
                while remaining > 0:
                    chunk = client_socket.recv(min(4096, remaining))
                    if not chunk:
                        break
                    f.write(chunk)
                    remaining -= len(chunk)
            print("File received and saved to:", file_path)
        except Exception as e:
            print("Error handling incoming file:", e)
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
def send_file(target_ip, target_port, file_path, target_dir):
    """
    Connects to the target computer and sends the selected file.
    The function creates a JSON header containing the target directory,
    file name, and file size, then sends the header (prefixed by its length)
    followed by the file content.
    """
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    header = {
        "target_dir": target_dir,
        "file_name": file_name,
        "file_size": file_size
    }
    header_json = json.dumps(header).encode()
    header_length = len(header_json)
    header_length_bytes = header_length.to_bytes(4, byteorder='big')
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((target_ip, target_port))
        s.sendall(header_length_bytes)
        s.sendall(header_json)
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                s.sendall(chunk)
    print("File sent successfully.")

# =============================================================================
# PART 4: GUI Application (Tkinter based)
# =============================================================================
class FileTransferApp:
    """
    Provides a simple GUI that:
      - Lists available computers on the network.
      - Lets the user select a file (or folder, if extended).
      - Asks for the destination folder on the target computer.
      - Initiates the file transfer.
    """
    def __init__(self, master):
        self.master = master
        master.title("Thunderbolt File Transfer")

        # Frame for connection details
        self.conn_frame = tk.Frame(master)
        self.conn_frame.pack(pady=10, padx=10, fill=tk.X)

        # IP Entry
        self.ip_label = tk.Label(self.conn_frame, text="Target IP:")
        self.ip_label.pack(side=tk.LEFT, padx=5)
        self.ip_entry = tk.Entry(self.conn_frame)
        self.ip_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        self.ip_entry.insert(0, "169.254.") # Default Thunderbolt network prefix

        # Port Entry
        self.port_label = tk.Label(self.conn_frame, text="Port:")
        self.port_label.pack(side=tk.LEFT, padx=5)
        self.port_entry = tk.Entry(self.conn_frame, width=6)
        self.port_entry.pack(side=tk.LEFT, padx=5)
        self.port_entry.insert(0, "5001")

        # Test Connection button
        self.test_conn_button = tk.Button(self.conn_frame, text="Test Connection", command=self.test_connection)
        self.test_conn_button.pack(side=tk.LEFT, padx=5)

        # Status label
        self.status_label = tk.Label(master, text="Status: Ready")
        self.status_label.pack(pady=5)

        # Button to select file or folder
        self.select_file_button = tk.Button(master, text="Select File/Folder", command=self.select_file)
        self.select_file_button.pack(pady=5)

        # Button to start the transfer
        self.transfer_button = tk.Button(master, text="Transfer", command=self.transfer_file)
        self.transfer_button.pack(pady=10)

        self.selected_file = None

    def test_connection(self):
        """Test the connection to the target computer."""
        target_ip = self.ip_entry.get().strip()
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
        """Opens a file dialog for the user to select a file to transfer."""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file = file_path
            self.status_label.config(text=f"Status: Selected file: {os.path.basename(file_path)}")

    def transfer_file(self):
        """Initiates the file transfer after ensuring a file and connection details are valid."""
        if not self.selected_file:
            messagebox.showwarning("No File", "Please select a file first.")
            return

        target_ip = self.ip_entry.get().strip()
        if not target_ip:
            messagebox.showwarning("No IP", "Please enter the target IP address.")
            return

        try:
            target_port = int(self.port_entry.get().strip())
        except ValueError:
            messagebox.showwarning("Invalid Port", "Please enter a valid port number.")
            return

        # Ask the user for the destination folder on the target computer
        target_dir = simpledialog.askstring("Target Directory", 
            "Enter destination directory on target computer:\n"
            "(e.g., C:\\Users\\username\\Downloads)")
        if not target_dir:
            messagebox.showwarning("No Directory", "Destination directory is required.")
            return

        try:
            self.status_label.config(text="Status: Transferring file...", fg="blue")
            send_file(target_ip, target_port, self.selected_file, target_dir)
            self.status_label.config(text="Status: File transferred successfully!", fg="green")
            messagebox.showinfo("Success", "File transferred successfully!")
        except Exception as e:
            self.status_label.config(text=f"Status: Transfer failed - {str(e)}", fg="red")
            messagebox.showerror("Error", f"File transfer failed: {e}")

# =============================================================================
# PART 5: Main Execution
# =============================================================================
if __name__ == "__main__":
    # Step 1: Check (and auto-install if needed) the Thunderbolt driver.
    if not check_and_install_thunderbolt_driver():
        print("Driver check failed. Exiting application.")
        exit(1)

    # Step 2: Start the file transfer server in the background.
    server = FileTransferServer(host='', port=5001)
    server.daemon = True  # Ensures the server thread exits when the main program does.
    server.start()

    # Step 3: Launch the GUI.
    root = tk.Tk()
    app = FileTransferApp(root)
    root.mainloop()

    # (Optional) When the GUI is closed, stop the server.
    server.stop()
