# Telegram-Based Keylogger POC

## Educational Security Research Tool

This project is an educational Proof-of-Concept (POC) tool designed for security research and demonstration purposes only. It showcases functionalities typically found in malware, such as keystroke capture, remote data exfiltration, and command and control capabilities, utilizing Telegram as a communication channel.

**DISCLAIMER:** This tool is for **EDUCATIONAL AND ETHICAL USE ONLY**. Do not use it on any system you do not own or do not have explicit permission to test. Unauthorized use of this software is illegal and unethical. The author is not responsible for any misuse or damage caused by this software.

## Features

-   **Cross-Platform Keystroke Capture:** Demonstrates how keystrokes can be logged.
-   **Remote Data Exfiltration:** Shows how captured data can be sent to a remote server (Telegram bot).
-   **Remote Command and Control (C2):** Illustrates basic remote command execution capabilities.
-   **System Information Collection:** Gathers details about the target system.
-   **Screenshot Capture:** Captures screenshots of the target's desktop.
-   **Clipboard Monitoring:** Monitors and extracts content from the clipboard.
-   **Microphone Recording:** Records audio from the system's microphone.
-   **Webcam Capture:** Captures images from the system's webcam.
-   **Network Information:** Collects public and local IP addresses and IP-based geolocation information.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/NIZBAN786/KeyLogBot
    cd KeyLogBot
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    ```

3.  **Activate the virtual environment:**
    *   **Windows:**
        ```bash
        .\venv\Scripts\activate
        ```
    *   **Linux/macOS:**
        ```bash
        source venv/bin/activate
        ```

4.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

5.  **Set up Telegram Bot:**
    *   Create a new Telegram Bot via BotFather. Obtain your `BOT_TOKEN`.
    *   Get your `CHAT_ID` by sending a message to your bot and then visiting `https://api.telegram.org/bot<BOT_TOKEN>/getUpdates`.

6.  **Configure Environment Variables:**
    Create a `.env` file in the project root directory with the following content:
    ```
    BOT_TOKEN=YOUR_TELEGRAM_BOT_TOKEN
    CHAT_ID=YOUR_TELEGRAM_CHAT_ID
    ENCRYPTION_KEY=YOUR_FERNET_ENCRYPTION_KEY
    ```
    *   You can generate a Fernet encryption key using Python:
        ```python
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        print(key.decode())
        ```

## Usage

To run the keylogger, execute the main Python script:

```bash
python telegram_keylogger.py
```

Once running, the tool will begin monitoring and exfiltrating data to your configured Telegram chat.

## Project Structure

-   `telegram_keylogger.py`: The main script containing the core logic for data collection, exfiltration, and C2.
-   `requirements.txt`: Lists all Python dependencies.
-   `.env`: Configuration file for sensitive information like API tokens and chat IDs.
-   `build/`, `dist/`: Directories for compiled executables (e.g., using PyInstaller).

## Contributing

Contributions are welcome for educational purposes. Please open an issue or submit a pull request.

## License

This project is open-source and available under the MIT License. See the `LICENSE` file for more details.#
