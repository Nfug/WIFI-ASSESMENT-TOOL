#--------1)IMPORT LIBRARIES & PROJECT SETUP---------
import os
import csv
import json
import re
import shutil
import subprocess
from datetime import datetime

tabulate = None

#project:folders
DATA_DIR = "data"
LOG_DIR = "logs"
REPORT_DIR = "reports"
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

#configurations
DEFAULT_INTERFACE = None
SCAN_DURATION = 10  # seconds
LOG_FILE = os.path.join(LOG_DIR, 'wifi_tool.log')
RESULTS_FILE = os.path.join(DATA_DIR, 'network.csv')

#Tool information
TOOL_NAME = "WiFi Security Assessment Tool"
TOOL_VERSION = "1.0"
AUTHOR = "0000"
DESCRIPTION = "A tool for assessing WiFi security" \
" by scanning networks and analyzing vulnerabilities."

#Main Menu
def show_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=" * 60)
    print(f"{TOOL_NAME} v{TOOL_VERSION}")
    print("=" * 60)
    print("1.List wireless interfaces")
    print("2.Scan for WiFi networks")
    print("3.Analyze  selected network")
    print("4.Generate report (CSV)")
    print("5.View saved results")
    print("6.Exit")
    print("-" * 60)

#-------2)WIFI NETWORK DISCOVERY & INFORMATION--------
#function :Get available wireless interfaces
def get_wireless_interfaces():
    if os.name == 'nt':
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'interfaces'],
            capture_output=True,
            text=True,
            check=False,
        )
        return re.findall(r'^\s*Name\s*:\s*(.+)$', result.stdout, re.MULTILINE)
    net_dir = '/sys/class/net'
    return [iface for iface in os.listdir(net_dir) if iface != 'lo'] if os.path.isdir(net_dir) else []

#function:Scan for WiFi networks
def scan_wifi_networks(interface, timeout=5):
    if os.name == 'nt':
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
            capture_output=True,
            text=True,
            check=False,
        )
        return parse_windows_networks(result.stdout)
    if shutil.which('iwlist') is None:
        print('[-] WiFi scanning requires the iwlist command on Linux.')
        return []
    print(f"Scanning for WiFi networks on interface {interface} please wait {timeout} seconds...")
    result = subprocess.run(['sudo', 'iwlist', interface, 'scan'], capture_output=True, text=True, check=False)
    scan_file = os.path.join(DATA_DIR, 'scan_output.txt')
    with open(scan_file, 'w', encoding='utf-8') as scan_handle:
        scan_handle.write(result.stdout)
    return [network for cell in result.stdout.split('Cell ') if 'ESSID' in cell
            for network in [parse_network_info(cell)] if network]


def parse_windows_networks(output):
    networks = []
    for block in re.split(r'(?=^\s*SSID\s+\d+\s*:)', output, flags=re.MULTILINE)[1:]:
        ssid_match = re.search(r'^\s*SSID\s+\d+\s*:\s*(.*)$', block, re.MULTILINE)
        bssid_match = re.search(r'^\s*BSSID\s+\d+\s*:\s*([0-9a-f:]{17})$', block, re.MULTILINE | re.IGNORECASE)
        signal_match = re.search(r'^\s*Signal\s*:\s*(\d+)%', block, re.MULTILINE)
        channel_match = re.search(r'^\s*Channel\s*:\s*(\d+)', block, re.MULTILINE)
        encryption_match = re.search(r'^\s*Authentication\s*:\s*(.+)$', block, re.MULTILINE)
        if not ssid_match or not bssid_match:
            continue
        signal = signal_match.group(1) if signal_match else '0'
        networks.append({
            'BSSID': bssid_match.group(1),
            'ESSID': ssid_match.group(1).strip(),
            'Channel': channel_match.group(1) if channel_match else 'N/A',
            'Frequency': 'N/A',
            'Quality': f'{signal}/100',
            'Signal': int(signal),
            'Encryption': encryption_match.group(1).strip() if encryption_match else 'Open',
        })
    return networks

# Function to parse network information from scan results
def parse_network_info(cell):
    def match(pattern, default='N/A'):
        found = re.search(pattern, cell)
        return found.group(1) if found else default

    network = {
        'BSSID': match(r'Address\s*:\s*([0-9A-Fa-f:]{17})'),
        'ESSID': match(r'ESSID:\s*"([^"]*)"', ''),
        'Channel': match(r'Channel\s*:?\s*(\d+)'),
        'Frequency': match(r'Frequency\s*:\s*([\d.]+\s*GHz)'),
        'Quality': match(r'Quality[=:\s]*(\d+/\d+)'),
    }
    network['Encryption'] = detect_encryption(cell)
    network['Signal'] = calculate_signal_strength(network['Quality'])
    return network

# Function to detect encryption type
def detect_encryption(cell):
    if "WPA2" in cell:
        return "WPA2"
    elif "WPA" in cell:
        return "WPA"
    elif "WEP" in cell:
        return "WEP"
    else:
        return "Open"

# Function to calculate signal strength from quality
def calculate_signal_strength(quality):
    try:
        q, max_q = map(int, quality.split('/'))
        return int((q / max_q) * 100) if max_q else 0
    except (ValueError, AttributeError):
        return 0


#-----------3)ANALYZE SIGNAL,CHANNEL,&MANAGE RESULTS---------
# Function:Analyze signal strength
def analyze_signal(networks):
    for network in networks:
        try:
            signal = int(str(network.get('Signal', -100)).replace('%', '').replace('dBm', '').strip())
            quality = signal if 0 <= signal <= 100 else 2 * (signal + 100)
            quality = max(0, min(100, quality))
            network['Quality(%)'] = quality
        except:
            network['Quality(%)'] = 0
#Function :channel analysis
def analyze_channels(networks):
    channel_count={}
    for network in networks:
        channel=network.get('Channel','N/A')
        if channel:
            channel_count[channel]=channel_count.get(channel,0)+1
    return channel_count
#Function:filter networks
def filter_networks(networks,security=None,ssid=None,min_quality=0):
    filtered=[]
    for network in networks:
        if security and network.get('Encryption','')!=security:
          continue
        if ssid and ssid.lower()not in network.get('ESSID','').lower():
          continue
        if int(network.get('Quality(%)',0))<min-quality: # type: ignore
          continue
        filtered.append(network)
    return filtered
#Function:Save results to CSV
def save_to_csv(networks, filename=os.path.join(DATA_DIR, 'wifi-results.csv')):
    if not networks:
           print('[-]No data to save.')
           return
    fields=['ESSID','BSSID','Channel','Frequency','Signal','Quality(%)','Encryption']
    with open(filename,'w',newline='') as csvfile:
                       writer=csv.DictWriter(csvfile,fieldnames=fields)
                       writer.writeheader()
                       for network in networks:
                           writer.writerow({field: network.get(field, 'N/A') for field in fields})
    print(f"Results saved to {filename}")
#Function:Display results in table format
def display_results(networks):
    if not networks:
        print("No networks found.")
        return
    headers = ['ESSID', 'BSSID', 'Channel', 'Frequency', 'Signal', 'Quality(%)', 'Encryption']
    table = [[network.get(header, 'N/A') for header in headers] for network in networks]
    if tabulate:
        print(tabulate(table, headers=headers, tablefmt='grid'))
    else:
        print(','.join(headers))
        for row in table:
            print(','.join(str(value) for value in row))
    print(f"Total networks found: {len(networks)}")
    print(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    for i, network in enumerate(networks, start=1):
        print(f"{i}. {network.get('ESSID', 'N/A')} - {network.get('BSSID', 'N/A')} - {network.get('Encryption', 'N/A')} - Signal: {network.get('Signal', 'N/A')} - Quality: {network.get('Quality(%)', 'N/A')}%")

#-----------4)SECURITY ASSESSMENT & REPORT GENERATION---------
# function:Assess security level
def assess_security(network):
    enc = network.get('Encryption', '').upper()
    if 'WPA3' in enc:
        return 'SECURE (WPA3)'
    elif 'WPA2' in enc:
        return 'MODERATE (WPA2)'
    elif 'WEP' in enc:
        return 'WEAK (WEP)'
    elif enc == 'OPEN' or enc == '':
        return 'UNSECURED (OPEN)'
    else:
        return 'UNKNOWN'
#function:Generate report table
def generate_report(networks):
    report=[]
    report.append(['ESSID','BSSID','Channel','Frequency','Signal','Quality(%)','Encryption','Security Level'])
    for network in networks:
        level=assess_security(network)
        report.append({
            'ESSID':network.get('ESSID',''),
            'BSSID':network.get('BSSID',''),
            'Channel':network.get('Channel',''),
            'Frequency':network.get('Frequency',''),
            'Signal':network.get('Signal',''),
            'Quality(%)':network.get('Quality(%)',''),
            'Encryption':network.get('Encryption',''),
            'Security Level':level
        })
    return report
    #function:print record table
def print_report(report):
    print('\n====== WiFi Security Assessment Report ======\n')
    if tabulate:
        print(tabulate(report[1:], headers=report[0], tablefmt='grid'))
    else:
        print(report)
#Function:Save report to file
def save_report(report,filename='wifi-security-report.csv'):
    with open(filename,'w',newline='') as csvfile:
        writer=csv.writer(csvfile)
        for row in report:
            writer.writerow(row)
    print(f"Report saved to {filename}")

#---------5)EXPORT,WORKFLOW,USAGE&NOTES---------
#Function:Export results to CSV
def export_to_csv(networks, filename='wifi-results.csv'):
    if not networks:
        print('[-] No data found to export.')
        return
    fields = ['ESSID', 'BSSID', 'Channel', 'Frequency', 'Signal', 'Quality(%)', 'Encryption']
    with open(filename, 'w', newline='') as file_handle:
        writer = csv.DictWriter(file_handle, fieldnames=fields)
        writer.writeheader()
        for row in networks:
            writer.writerow({field: row.get(field, '') for field in fields})
    print(f'[+] data exported to {filename}')
#Function:Export Results to JSON
def export_to_json(networks,filename='wifi_results.json'):
    if not networks:
        print('[-]No data to export.')
        return
    with open(filename, 'w', encoding='utf-8') as file_handle:
        json.dump(networks, file_handle, indent=4)
    print(f'[+] Data exported to {filename}')
#Function:Main Workflow
def main():
    interfaces = get_wireless_interfaces()
    if not interfaces:
        print('[-] No wireless interfaces found, or this platform is unsupported.')
        return
    networks = scan_wifi_networks(interfaces[0], timeout=10)
    analyze_signal(networks)
    display_results(networks)
    export_to_csv(networks)
    export_to_json(networks)
    print("\n[+] Scan completed. Stay secure!")


if __name__ == '__main__':
    main()