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

        # Label and listbox for available computers
        self.label = tk.Label(master, text="Available Computers:")
        self.label.pack(pady=5)

        self.listbox = tk.Listbox(master, width=50)
        self.listbox.pack(padx=10)

        self.refresh_button = tk.Button(master, text="Refresh List", command=self.refresh_computers)
        self.refresh_button.pack(pady=5)

        # Button to select file or folder (currently uses file dialog)
        self.select_file_button = tk.Button(master, text="Select File/Folder", command=self.select_file)
        self.select_file_button.pack(pady=5)

        # Button to start the transfer
        self.transfer_button = tk.Button(master, text="Transfer", command=self.transfer_file)
        self.transfer_button.pack(pady=10)

        self.selected_file = None
        self.refresh_computers()

    def refresh_computers(self):
        """Refresh the list of available computers using the 'net view' command."""
        self.listbox.delete(0, tk.END)
        try:
            output = subprocess.check_output("net view", shell=True, text=True)
            lines = output.splitlines()
            for line in lines:
                # Lines with computer names typically start with '\\'
                if line.strip().startswith("\\\\"):
                    comp = line.split()[0].strip("\\")
                    self.listbox.insert(tk.END, comp)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to retrieve computers: {e}")

    def select_file(self):
        """Opens a file dialog for the user to select a file to transfer."""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file = file_path
            messagebox.showinfo("File Selected", f"Selected file: {file_path}")

    def transfer_file(self):
        """Initiates the file transfer after ensuring a file and target are selected."""
        if not self.selected_file:
            messagebox.showwarning("No File", "Please select a file first.")
            return
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showwarning("No Target", "Please select a target computer from the list.")
            return

        target_computer = self.listbox.get(selection[0])
        try:
            # Resolve the computer name to an IP address.
            target_ip = socket.gethostbyname(target_computer)
        except Exception as e:
            messagebox.showerror("Error", f"Cannot resolve computer name: {e}")
            return

        # Ask the user for the destination folder on the target computer.
        target_dir = simpledialog.askstring("Target Directory", f"Enter destination directory on {target_computer}:")
        if not target_dir:
            messagebox.showwarning("No Directory", "Destination directory is required.")
            return

        try:
            send_file(target_ip, 5001, self.selected_file, target_dir)
            messagebox.showinfo("Success", "File transferred successfully!")
        except Exception as e:
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
