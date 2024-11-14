# SSH Client Emulator

An interactive SSH client emulator built with Python, leveraging the `paramiko` library and `curses` for a terminal-based user interface. This application allows you to customize SSH connection parameters and algorithms, providing detailed logging of the SSH negotiation process.

![SSH Client Emulator Screenshot](https://altenderfer.io/github/altenderfer-ssh-tool.png)

## Features

- **Interactive UI**: Navigate through connection settings and algorithm selections using keyboard controls.
- **Algorithm Customization**: Select specific Host Key Algorithms, KEX Algorithms, Ciphers, and MACs for your SSH connection.
- **Real-Time Logging**: View detailed SSH negotiation logs in real-time within the application.
- **Log Management**:
  - **Scroll Logs**: Scroll through logs using Page Up/Page Down keys.
  - **Save Logs**: Save session logs to a file (`session_log_dump.txt`) for later analysis.
  - **Clear Logs**: Clear the current log display within the application.
- **Color-Coded Interface**: Enhanced readability with color-coded logs and interface elements.
- **Threaded Connection Handling**: SSH connections are handled in a separate thread to keep the UI responsive.

### To-Do
- When drilling down selected Algorithms, KEX, Ciphers, Macs -> Only traceback error appears (Update to have more detailed information)



## Installation

### Prerequisites

- **Python**: Version 3.x
- **Packages**:
  - `paramiko`
- **Operating System**: Linux or macOS (due to the use of `curses`)

### Steps

1. **Clone the Repository**

   ```bash
   git clone https://github.com/altenderfer/altenderfer-ssh-tool.git
   cd altenderfer-ssh-tool
   ```

2. **Install Required Packages**

   ```bash
   pip install paramiko
   ```

## Usage

Run the application using:

```bash
python altenderfer-ssh-tool.py
```

### Navigation and Controls

- **Up/Down Arrow Keys**: Navigate between input fields and algorithm selections.
- **Enter**: Edit an input field or select an algorithm category.
- **In Edit Mode**:
  - **Type**: Input your data.
  - **Arrow Keys**: Navigate within the text input (if supported by your terminal).
- **In Algorithm Selection Mode**:
  - **Up/Down Arrow Keys**: Navigate algorithm options.
  - **Spacebar**: Select/Deselect an algorithm.
  - **Enter**: Confirm selections and exit.
- **Actions**:
  - **C**: Connect to the SSH server.
  - **L**: Clear the log window.
  - **S**: Save the current session log to `session_log_dump.txt`.
  - **Q**: Quit the application.
- **Log Scrolling**:
  - **Page Up/Page Down**: Scroll the log window.

### Example Steps

1. **Set Connection Parameters**: Use the arrow keys to navigate to each field and press **Enter** to edit the IP address, port, username, and password.

2. **Customize Algorithms**: Navigate to the algorithm categories and press **Enter** to select/deselect specific algorithms.

3. **Connect**: Press **C** to initiate the SSH connection with your specified settings.

4. **View Logs**: Observe the real-time logs of the SSH negotiation process in the right panel.

5. **Scroll Logs**: Use **Page Up** and **Page Down** to scroll through the logs if they exceed the window size.

6. **Save Logs**: Press **S** to save the session logs to a file.

## Requirements

- **Python**: Version 3.x
- **Libraries**:
  - `paramiko`: For SSH protocol handling.
  - `curses`: For creating the text-based user interface (standard with most Python installations on Unix-based systems).
- **Terminal**: A terminal that supports ANSI escape codes and `curses` library functionality.

## License

[MIT License](LICENSE)

## Author

**Kyle Altenderfer**

- **Website**: [https://altenderfer.io/](https://altenderfer.io/)
- **GitHub**: [https://github.com/yourusername](https://github.com/altenderfer)

## Tags

- SSH Client
- Python
- Paramiko
- Curses
- Terminal Application
- Network Tools
- SSH Algorithms
- SSH Debugging
- Interactive CLI

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## Acknowledgments

- **Paramiko**: [https://www.paramiko.org/](https://www.paramiko.org/)
- **Curses**: Python's built-in library for creating text-based user interfaces.
