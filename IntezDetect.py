import argparse
import os
import requests
import time
import psutil
from prettytable import PrettyTable
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
from tabulate import tabulate
from tqdm import tqdm

print('\033[34;1m' + """  

██╗███╗░░██╗████████╗███████╗███████╗██████╗░███████╗████████╗███████╗░█████╗░████████╗
██║████╗░██║╚══██╔══╝██╔════╝╚════██║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗╚══██╔══╝
██║██╔██╗██║░░░██║░░░█████╗░░░░███╔═╝██║░░██║█████╗░░░░░██║░░░█████╗░░██║░░╚═╝░░░██║░░░
██║██║╚████║░░░██║░░░██╔══╝░░██╔══╝░░██║░░██║██╔══╝░░░░░██║░░░██╔══╝░░██║░░██╗░░░██║░░░
██║██║░╚███║░░░██║░░░███████╗███████╗██████╔╝███████╗░░░██║░░░███████╗╚█████╔╝░░░██║░░░
╚═╝╚═╝░░╚══╝░░░╚═╝░░░╚══════╝╚══════╝╚═════╝░╚══════╝░░░╚═╝░░░╚══════╝░╚════╝░░░░╚═╝░░░
 
                   -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                   +        ..| IntezDetect v1.0 |..      +
                   -                                      -
                   -              By: Hamoud Alharbi      -
                   +         Twitter: @Hamoud__2          +
                   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

""" + '\033[0m')
                                                                            
API_KEY = 'YOUR_API_KEY'
INTEZER_API_URL = 'https://analyze.intezer.com/api/v2-0'
MAX_WORKERS = 5 

def color_malicious(text):
    if "malicious" in text.lower():
        return text.replace("malicious", colored("malicious", "red"))
    elif "suspicious" in text.lower():
        return text.replace("suspicious", colored("suspicious", "yellow"))
    return text

def display_results(results):
    result = results.get('result', {})

    table = [
        [colored("File Name", "cyan"), result.get("file_name", "N/A")],
        [colored("File Type", "cyan"), result.get("file_type", "N/A")],
        [colored("SHA256", "cyan"), result.get("sha256", "N/A")],
        [colored("Verdict", "cyan"), colored(result.get("verdict", "N/A"), "yellow" if "suspicious" in result.get("verdict", "").lower() else "red" if result.get("verdict", "N/A") == "malicious" else "green")],
        [colored("Sub-Verdict", "cyan"), colored(result.get("sub_verdict", "N/A"), "yellow" if "suspicious" in result.get("sub_verdict", "").lower() else "red" if result.get("sub_verdict", "N/A") == "malicious" else "green")],
        [colored("Analysis Time", "cyan"), result.get("analysis_time", "N/A")],
        [colored("Analysis URL", "cyan"), result.get("analysis_url", "N/A")],
        [colored("Threat Name", "cyan"), result.get("threat_name", "N/A")],
        [colored("Scan Duration", "cyan"), result.get("scan_duration", "N/A")],
        [colored("Analysis ID", "cyan"), result.get("analysis_id", "N/A")]
    ]

    headers = [colored("Attribute", "magenta"), colored("Value", "magenta")]
    print(tabulate(table, headers=headers, tablefmt="fancy_grid"))

def analyze_file(file_path, headers, pbar=None):
    with open(file_path, 'rb') as file:
        files = {'file': (file_path, file)}
        response = requests.post(f'{INTEZER_API_URL}/analyze', headers=headers, files=files)
        response.raise_for_status()
        json_response = response.json()
        analysis_id = json_response['result_url'].split('/')[-1]

    def get_analysis_status():
        response = requests.get(f'{INTEZER_API_URL}/analyses/{analysis_id}', headers=headers)
        response.raise_for_status()
        return response.json()['status']

    while (status := get_analysis_status()) in ['in_progress', 'queued']:
        time.sleep(10)

    if pbar is not None:
        pbar.update(1)

    if status == 'succeeded':
        print(f'Analysis completed successfully for file: {file_path}')
        response = requests.get(f'{INTEZER_API_URL}/analyses/{analysis_id}', headers=headers)
        response.raise_for_status()
        results = response.json()
        return results
    else:
        print(f'Analysis failed for file: {file_path} with status: {status}')
        return None

parser = argparse.ArgumentParser(description='Scan a file or a directory using Intezer Analyze API.')
parser.add_argument('-f', '--file', metavar='FILE', type=str, help='The file to scan.')
parser.add_argument('-d', '--directory', metavar='DIRECTORY', type=str, help='The directory to scan.')
args = parser.parse_args()

response = requests.post(f'{INTEZER_API_URL}/get-access-token', json={'api_key': API_KEY})
response.raise_for_status()
access_token = response.json()['result']
headers = {'Authorization': f'Bearer {access_token}'}

if args.file:
    file_path = args.file
    if not os.path.exists(file_path):
        print(f'File not found: {file_path}')
        exit(1)

    if os.path.isfile(file_path):
        print(f'Starting analysis for file: {file_path}')
        results = analyze_file(file_path, headers)
        if results is not None:
            display_results(results)
    else:
        print(f'File is a directory. Use -d option to scan directories.')
elif args.directory:
    directory_path = args.directory
    if not os.path.exists(directory_path):
        print(f'Directory not found: {directory_path}')
        exit(1)

    if os.path.isdir(directory_path):
        files_to_scan = []
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                files_to_scan.append(file_path)

        print(f'Starting analysis for {len(files_to_scan)} files in directory: {directory_path}')
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            with tqdm(total=len(files_to_scan)) as pbar:
                for file_path in files_to_scan:
                    future = executor.submit(analyze_file, file_path, headers, pbar)
                    futures.append(future)

            for future in as_completed(futures):
                results = future.result()
                if results is not None:
                    display_results(results)
    else:
        print(f'File is not a directory. Use -f option to scan files.')
else:
    parser.print_help()
