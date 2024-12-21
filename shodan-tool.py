import shodan
import re
import json
import os
from datetime import datetime
from time import sleep
from filelock import FileLock
import requests
import logging
from tabulate import tabulate
import sys

def create_env_file():
    """Create a .env file and populate it with necessary variables."""
    if not os.path.exists('.env'):
        print(".env file not found. Creating one now.")
        api_key = input("Enter your Shodan API key: ").strip()
        if not api_key:
            print("Error: API key cannot be empty!")
            sys.exit(1)
        with open('.env', 'w') as f:
            f.write(f'SHODAN_API_KEY={api_key}\n')
        print(".env file created successfully with the provided API key.")
    else:
        print(".env file already exists.")

def load_env_file():
    """Load environment variables from the .env file."""
    if os.path.exists('.env'):
        with open('.env') as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    key, value = line.strip().split('=', 1)
                    os.environ[key] = value
        print("Environment variables loaded successfully.")
    else:
        print(".env file not found! Please create one.")
        create_env_file()

# Step 1: Load or create the .env file
load_env_file()

# Step 2: Get the Shodan API Key from environment variables
api_key = os.getenv("SHODAN_API_KEY")

if not api_key:
    print("API key is required! Please set the SHODAN_API_KEY environment variable.")
    sys.exit(1)

print(f"Using Shodan API Key: {api_key[:5]}...")  # Just printing the first 5 characters to verify it's loaded

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load configuration settings from a JSON config file
def load_config() -> dict:
    config_file = 'config.json'
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            return json.load(f)
    else:
        default_config = {
            "result_file": "search_results.json",
            "page_size": 10,
            "default_api_key": ""
        }
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=4)
        return default_config

# Save settings to config file
def save_config(config: dict) -> None:
    with open('config.json', 'w') as f:
        json.dump(config, f, indent=4)

def initialize_api(api_key: str) -> shodan.Shodan:
    """Initialize the Shodan API."""
    return shodan.Shodan(api_key)

def is_valid_ip(ip: str) -> bool:
    """Validate the format of an IP address."""
    return re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip) is not None

def save_results_to_file(results: dict, query: str, filename: str = "search_results.json") -> None:
    """Save search results to a file with file integrity."""
    lock = FileLock(f"{filename}.lock")
    with lock:
        data = []
        if os.path.exists(filename):
            with open(filename, "r") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    logging.error("Error reading the results file. It might be corrupted.")
                    return
        data.append({
            "timestamp": datetime.now().isoformat(),
            "query": query,
            "results": results
        })
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
    print(f"Search results for '{query}' saved successfully!")

def format_search_results(results: dict) -> str:
    """Format the search results for output."""
    if not results.get('matches'):
        return "No results found."

    output = ""
    total_results = len(results['matches'])

    table = []
    for match in results['matches']:
        table.append([
            match['ip_str'],
            match.get('org', 'n/a'),
            ', '.join(match.get('hostnames', ['n/a']))
        ])
    
    output += tabulate(table, headers=["IP", "Organization", "Hostnames"], tablefmt="grid")
    return output

def save_search_history(query: str, search_history: list, results_count: int) -> None:
    """Save search query with a timestamp to the history."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    search_history.append({
        'query': query,
        'timestamp': timestamp,
        'results_count': results_count
    })
    if len(search_history) > 10:
        search_history.pop(0)

def review_search_history(search_history: list) -> None:
    """Print the search history."""
    if not search_history:
        print("No search history available.")
        return
    print("\n=== Search History ===")
    for entry in search_history:
        print(f"[{entry['timestamp']}] Query: {entry['query']} | Results Found: {entry['results_count']}")

def get_host_info(api: shodan.Shodan, ip_address: str) -> dict:
    """Get information about a specific IP address, including open ports and vulnerabilities."""
    result = {}
    if not is_valid_ip(ip_address):
        print(f"Invalid IP address format: {ip_address}")
        return result

    try:
        host_info = api.host(ip_address)
        result['ip_address'] = ip_address
        result['organization'] = host_info.get('org', 'n/a')
        result['location'] = f"{host_info.get('city', 'n/a')}, {host_info.get('country_name', 'n/a')}"
        result['hostnames'] = ', '.join(host_info.get('hostnames', ['n/a']))

        if 'ports' in host_info:
            result['open_ports'] = host_info['ports']
        else:
            result['open_ports'] = "None"
        
        # Handling vulnerabilities
        if 'vulns' in host_info:
            if isinstance(host_info['vulns'], dict):
                result['vulnerabilities'] = ', '.join(host_info['vulns'].keys())
            elif isinstance(host_info['vulns'], list):
                result['vulnerabilities'] = ', '.join(host_info['vulns'])  # Assuming the list contains vulnerability IDs
            else:
                result['vulnerabilities'] = "Unknown format"
        else:
            result['vulnerabilities'] = "None"
        
    except shodan.APIError as e:
        logging.error(f"Error retrieving host information: {e}")
        print("Could not retrieve host information. Please try again later.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error: {e}")
        print("A network error occurred. Please check your connection.")

    return result

def get_api_usage(api: shodan.Shodan) -> None:
    """Get API usage statistics."""
    try:
        usage = api.info()
        print("API usage data:", usage)
        
        queries_made = usage.get('queries', 'N/A')
        queries_left = usage.get('queries_left', 'N/A')
        
        print(f"API usage: {queries_made} queries made.")
        print(f"API quota: {queries_left} queries remaining.")
    except shodan.APIError as e:
        logging.error(f"Error retrieving API info: {e}")
        print("Could not retrieve API information. Please try again later.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error: {e}")
        print("A network error occurred. Please check your connection.")

def rate_limit_check(api: shodan.Shodan) -> None:
    """Check if the rate limit has been exceeded."""
    usage = api.info()
    remaining_queries = usage['queries_left']
    if remaining_queries < 5:
        print(f"Warning: Only {remaining_queries} queries remaining. Please wait before continuing.")
        sleep(60)
        print("Resuming search...")

def lookup_domain(api: shodan.Shodan, domain: str, search_history: list) -> None:
    """Lookup information related to a domain name, including IPs and their details."""
    results_list = []
    
    try:
        results = api.search(f"hostname:{domain}")

        if not results['matches']:
            print(f"No results found for domain '{domain}'.")
            return
        
        print(f"\n=== Search Results for domain '{domain}' ===")
        print(f"Results found: {results['total']}\n")
        
        for match in results['matches']:
            ip = match['ip_str']
            # Check if the IP format is valid before calling get_host_info
            if is_valid_ip(ip):
                info = get_host_info(api, ip)
                results_list.append(info)  # Save each IP info
            else:
                print(f"Skipping invalid IP address: {ip}")
            
        save_search_history(domain, search_history, results['total'])

        # Prompt user for output file
        output_file = input("Enter output filename (including .json or .txt): ").strip()
        with open(output_file, 'w') as f:
            json.dump(results_list, f, indent=4)
        print(f"Results saved to '{output_file}' successfully!")  

    except shodan.APIError as e:
        logging.error(f"Error looking up domain: {e}")
        print("Could not retrieve information for the domain. Please try again later.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error: {e}")
        print("A network error occurred. Please check your connection.")

def search_devices(api: shodan.Shodan, query: str, search_history: list) -> None:
    """Search for services/devices based on user query."""
    results_list = []
    
    try:
        results = api.search(query)

        if not results['matches']:
            print(f"No results found for query '{query}'.")
            return
        
        print(f"\n=== Search Results for '{query}' ===")
        print(f"Results found: {results['total']}\n")
        
        for match in results['matches']:
            ip = match['ip_str']
            info = get_host_info(api, ip)  # Retrieve information for each IP
            results_list.append(info)  # Store results
        
        save_search_history(query, search_history, results['total'])

        # Prompt user for output file
        output_file = input("Enter output filename (including .json or .txt): ").strip()
        with open(output_file, 'w') as f:
            json.dump(results_list, f, indent=4)
        print(f"Results saved to '{output_file}' successfully!")  

    except shodan.APIError as e:
        logging.error(f"Error searching for devices: {e}")
        print("Could not complete your search. Please try again later.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error: {e}")
        print("A network error occurred. Please check your connection.")

def print_introduction() -> None:
    """Print a basic introduction about the script."""
    print("\nWelcome to the Shodan API Query Tool!")
    print("This script allows you to interact with the Shodan API to search for devices, retrieve host information,")
    print("and view SSL certificate details. You can also store your search results and keep track of your search history.")
    print("Make sure to have your Shodan API key ready. Let's get started!\n")

def main() -> None:
    config = load_config()
    print_introduction()
    
    api_key = config['default_api_key'] or input("Enter your Shodan API key (or leave blank to use saved key): ").strip()
    while not api_key:
        print("API key is required to use this tool.")
        api_key = input("Please enter a valid Shodan API key: ").strip()
    if api_key and not config['default_api_key']:
        config['default_api_key'] = api_key
        save_config(config)
    api = initialize_api(api_key)

    get_api_usage(api)
    search_history = []

    while True:
        print("\nMenu:")
        print("1. Get host information by IP")
        print("2. Search for services/devices")
        print("3. Lookup domain name")
        print("4. Review search history")
        print("5. Exit")
        choice = input("Choose an option (1-5): ").strip()

        if choice == '1':
            ip_address = input("Enter the IP address: ").strip()
            info = get_host_info(api, ip_address)
            print(json.dumps(info, indent=4))  # Display information for the IP

        elif choice == '2':
            query = input("Enter your search query: ").strip()
            search_devices(api, query, search_history)

        elif choice == '3':
            domain = input("Enter the domain name: ").strip()
            lookup_domain(api, domain, search_history)

        elif choice == '4':
            review_search_history(search_history)

        elif choice == '5':
            print("Exiting the program.")
            break

        else:
            print("Invalid option, please try again.")

if __name__ == "__main__":
    main()
