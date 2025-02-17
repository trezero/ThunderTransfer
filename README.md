# Thunder.py

Thunder.py is a Python-based application that enables high-speed file transfers between two Windows laptops over a Thunderbolt USB-C cable. The application checks for the necessary Thunderbolt drivers (installing them automatically if needed), sets up a file transfer server, and provides a simple graphical interface for users to drag and drop files to remote machines.

## Features

- **Driver Verification & Auto-Installation:**  
  Checks for Thunderbolt drivers using Windows commands and downloads/installs them automatically if missing.
  
- **File Transfer Server:**  
  Runs a background TCP server to receive files on the destination machine.

- **User-Friendly GUI:**  
  Provides a Tkinter interface for selecting files, viewing available computers on the network, and initiating file transfers.

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
   git clone https://github.com/your-username/thunder.git
   cd thunder
   ```

2. **Create a Virtual Environment (Optional):**
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

### Driver Installer
The application will check if the Thunderbolt driver is installed. If not detected, you have two options:

1. **Recommended Method**: Use Lenovo System Update / Lenovo Vantage
   - Download Lenovo System Update from: https://support.lenovo.com/solutions/ht003029
   - Run the System Update utility
   - Select and install the "Intel Thunderbolt Driver" package

2. **Manual Method**: Download from Lenovo Support
   - Visit https://support.lenovo.com
   - Enter your machine type (for ThinkPad P1 Gen 6)
   - Navigate to "Drivers & Software"
   - Filter by "Thunderbolt/USB"
   - Download and install the latest "Intel Thunderbolt Driver"

Note: Administrator privileges are required for driver installation.

### Port Configuration
The file transfer server listens on TCP port 5001 by default. Adjust this in the code if needed.

## Usage

### Running the Application
Execute the application with:
```bash
python thunder.py
```

### Driver Check & Installation
- On startup, the application checks for the presence of Thunderbolt drivers using the `driverquery` command
- If the driver is not detected, the script will prompt the user to install the driver using one of the methods above
- Note: Administrator privileges might be required for this step

### Using the GUI

1. **Available Computers:**
   - The main window displays a list of available computers on the network
   - Click "Refresh List" to update the list

2. **Select File/Folder:**
   - Click "Select File/Folder" to choose a file (or folder) to transfer

3. **Initiate Transfer:**
   - Select a target computer from the list
   - Click "Transfer"
   - Enter the destination directory on the target computer when prompted

### Background Server
The file transfer server runs in the background to receive incoming transfers. It saves received files to the specified destination folder on the receiving machine.

## Troubleshooting

### Driver Installation Failures
- Ensure that you are running the application with administrator rights
- Double-check the URL for the driver installer

### Network Connection Issues
- Verify that both laptops are connected using a Thunderbolt USB-C cable
- Confirm that both systems support Thunderbolt networking

### Permission Errors
- Make sure the destination directory exists and that you have write permissions on it

## Security Considerations
Thunder.py is designed for secure on-premises file transfers over a direct cable connection. For enhanced security, consider implementing additional encryption or authentication mechanisms if deploying in less controlled environments.

## Contributing
Contributions, bug reports, and suggestions are welcome. Feel free to fork the repository and submit a pull request with your improvements.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.

## Contact
For support or inquiries, please open an issue in the GitHub repository.
