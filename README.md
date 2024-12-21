---

# Shodan-Tool

This script interacts with the Shodan API to search for devices, retrieve host information, and manage search history. It's a command-line tool designed for security researchers and network administrators to quickly gather information about devices connected to the internet.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)

## Features

- Search for devices/services on the Shodan network.
- Retrieve detailed information about specified IP addresses.
- Lookup information related to domains.
- Save search results and review search history.
- Load configuration from a JSON file.

## Requirements

- Python 3.6 or higher
- Libraries: `shodan`, `requests`, `tabulate`, `filelock`, `python-dotenv` (for loading environment variables)
  
You can install the required libraries using pip:
```bash
pip install shodan requests tabulate filelock python-dotenv
```

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/fish-hue/Shodan-Tool.git
    cd Shodan-Tool
    ```

2. **Create a `.env` file**:
    The first time you run the program, it will prompt you to enter your Shodan API key and create a `.env` file to store it securely. Alternatively, you can create the `.env` file manually:
    ```bash
    touch .env
    ```

3. **Open the `.env` file** and add your API key:
    ```plaintext
    SHODAN_API_KEY=your_shodan_api_key_here
    ```

## Usage

1. **Run the Script**:
    ```bash
    python shodan_tool.py
    ```

2. **Interact with the Menu**:
   - Select an option by entering the corresponding number:
     1. Get host information by IP
     2. Search for services/devices
     3. Lookup domain name
     4. Review search history
     5. Exit

3. **Follow the Prompts**:
   - Provide input as prompted. The results will be displayed, and you will have the option to save them to a file.

## Configuration

The script uses a `config.json` file to store configuration settings. When the script runs for the first time, it will create this file with the default settings, including the result file name and other parameters. You can edit this file manually to adjust settings as required.

- **result_file**: Name of the file where search results will be saved.
- **page_size**: Number of results per page (not fully implemented yet).
- **default_api_key**: Your Shodan API key (optional).
