# ThunderTransfer

ThunderTransfer is a Python-based application that enables high-speed file transfers between two Windows laptops over a Thunderbolt USB-C cable. The application checks for the necessary Thunderbolt drivers (installing them automatically if needed), sets up a file transfer server, and provides a modern graphical interface for transferring files and folders to remote machines.

## Features

- **Driver Verification & Auto-Installation:**  
  Checks for Thunderbolt drivers using Windows commands and guides you through the installation process if missing.
  
- **File & Folder Transfer Support:**  
  - Transfer individual files or entire folders while maintaining directory structure
  - Automatic handling of nested directories and multiple files
  - Progress tracking during transfers

- **Modern User Interface:**  
  - Clean, modern design with improved visibility
  - Easy-to-use file and folder selection
  - Clear feedback on transfer status and file information

- **Smart History Management:**
  - Remembers previously used target IP addresses
  - Stores destination folders for each target IP
  - Quick access to frequently used destinations
  - Automatically updates usage history

- **High-Speed Direct Transfer:**  
  Utilizes a direct Thunderbolt network connection for rapid and secure file transfers.

## Prerequisites

- **Operating System:** Windows 10 or Windows 11
- **Python Version:** Python 3.7 or later
- **Hardware:** Both laptops must have Thunderbolt 3 (or newer) USB-C ports and support Thunderbolt networking
- **Administrator Rights:** Required for installing drivers
- **Network Setup:** Ensure both systems are directly connected via a certified Thunderbolt USB-C cable

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/your-username/ThunderTransfer.git
   cd ThunderTransfer
   ```

2. **Create a Virtual Environment (Optional but recommended):**
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

### Driver Installation
The application will check if the Thunderbolt driver is installed. If not detected, you have two options:

1. **Recommended Method**: Use Lenovo System Update / Lenovo Vantage
   - Download Lenovo System Update from: https://support.lenovo.com/solutions/ht003029
   - Run the System Update utility
   - Select and install the "Intel Thunderbolt Driver" package

2. **Manual Method**: Download from Lenovo Support
   - Visit https://support.lenovo.com
   - Enter your machine type
   - Navigate to "Drivers & Software"
   - Filter by "Thunderbolt/USB"
   - Download and install the latest "Intel Thunderbolt Driver"

Note: Administrator privileges are required for driver installation.

## Usage

### Running the Application
Execute the application with:
```bash
python thunder.py
```

### Using the Interface

1. **Connection Settings:**
   - Your local Thunderbolt IP is displayed at the top
   - Use the "Refresh" button to update your IP
   - Select a target IP from the dropdown or type a new one
   - Default port is 5001

2. **Managing Destinations:**
   - Select from previously used destinations in the dropdown
   - Click "New" to add a new destination folder
   - Destinations are saved per target IP
   - Most recently used destinations appear first

3. **File/Folder Transfer:**
   - Click "Select File/Folder" to choose what to transfer
   - The interface will show file/folder details:
     - For files: Name and size
     - For folders: Path and total number of files
   - Click "Transfer" to start the transfer process

4. **History Management:**
   - Transfer history is automatically saved
   - History is stored in `~/.thundertransfer/transfer_history.json`
   - Includes target IPs and their associated destinations
   - Timestamps track when destinations were last used

### Background Server
The file transfer server runs in the background to receive incoming transfers. It automatically:
- Creates destination directories if they don't exist
- Maintains folder structure for folder transfers
- Handles multiple files in sequence
- Provides progress feedback during transfers

## Troubleshooting

### Connection Issues
1. **IP Address Problems:**
   - Ensure both computers are connected via Thunderbolt cable
   - Check that both machines have Thunderbolt IPs (usually starting with 169.254)
   - Use the "Test Connection" button to verify connectivity

2. **Transfer Failures:**
   - Verify the destination path exists on the target machine
   - Ensure you have write permissions for the destination
   - Check that the target machine is running ThunderTransfer
   - Verify the port (5001) is not blocked by firewall

### Driver Installation
- Ensure you have administrator rights
- If automatic installation fails, try the manual installation method
- Restart both computers after driver installation

## Data Storage
- Transfer history is stored in: `~/.thundertransfer/transfer_history.json`
- The history file is created automatically on first use
- You can safely delete the history file to reset saved destinations
