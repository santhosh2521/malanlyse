import argparse
import requests
import os
import hashlib
import sqlite3
import networkx as nx
import pandas as pd
import json
from tqdm import tqdm
from networkx.algorithms import isomorphism
import subprocess
from yaspin import yaspin
# Setup paths and variables
 
install_dir = f"D:/dms_daa_el/sc0pe_Base"
db_url = "https://raw.githubusercontent.com/CYB3RMX/MalwareHashDB/main/HashDB"
db_path = f"{install_dir}/HashDB"
csv_path = f"HashDB.csv"
spinner = yaspin()

# Downloading the HashDB
def download_db():
    os.makedirs(install_dir, exist_ok=True)
    response = requests.get(db_url, stream=True)
    total_size = int(response.headers.get('content-length', 0))
    block_size = 1024

    print("Downloading HashDB...")
    with open(db_path, 'wb') as db_file:
        for data in tqdm(response.iter_content(block_size), total=total_size // block_size, unit='KB', unit_scale=True):
            db_file.write(data)
    print("Download complete.")

# Checking if the database exists, if not download it
def check_db():
    if not os.path.isfile(db_path):
        download_db()
    return sqlite3.connect(db_path)

# Hashing the binary file using MD5
def get_file_hash(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# KMP search algorithm implementation
def kmp_search(pattern, text):
    lps = [0] * len(pattern)
    j = 0
    compute_lps(pattern, lps)

    i = 0
    while i < len(text):
        if pattern[j] == text[i]:
            i += 1
            j += 1

        if j == len(pattern):
            return True  # Pattern found
            j = lps[j - 1]
        elif i < len(text) and pattern[j] != text[i]:
            if j != 0:
                j = lps[j - 1]
            else:
                i += 1

    return False  # Pattern not found

def compute_lps(pattern, lps):
    length = 0
    i = 1
    while i < len(pattern):
        if pattern[i] == pattern[length]:
            length += 1
            lps[i] = length
            i += 1
        else:
            if length != 0:
                length = lps[length - 1]
            else:
                lps[i] = 0
                i += 1

# Load the ransomware graph from the JSON file
def load_ransomware_graph(json_file_path):
    with open(json_file_path, 'r') as file:
        graph_data = json.load(file)
    
    graph = nx.DiGraph()
    graph.add_edges_from((edge['from'], edge['to']) for edge in graph_data['edges'])
    return graph

# Define base CFGs for known ransomware patterns
def get_base_ransomware_patterns():
    base_patterns = []
    
    # Example Pattern 1: WannaCry
    wannacry_pattern = nx.DiGraph()
    wannacry_pattern.add_edges_from([
        ("set","InitializeCriticalSection"),
        ("set","LeaveCriticalSection"),
        ("set","EnterCriticalSection"),
        ("set", "WriteFile"),
        ("set", "CloseHandle"),
        ("set","RegCreateKeyW"),
        ("set","CryptReleaseContext"),
        ("set","OpenServiceA"),
        ("set","StartServiceA"),
        ("set","LoadResource"),
        ("set","LockResource"),
        ("set","WNetAddConnection2A")
    ])
    base_patterns.append(("WannaCry1", wannacry_pattern))
    
    # Example Pattern 2: GrandCrab
    grandcrab_pattern = nx.DiGraph()
    grandcrab_pattern.add_edges_from([
        ("set", "InternetOpenA"),
        ("set", "InternetConnectA"),
        ("set", "WriteFile"),
        ("set", "CloseHandle"),
        ("set","RegCreateKeyW"),
        ("set","InitializeCriticalSectionAndSpinCount"),
        ("set","LeaveCriticalSection"),
        ("set","EnterCriticalSection"),
        ("set","FlushFileBuffers"),
        ("set","VirtualLock"),
        ("set","IsDebuggerPresent")
    ])
    base_patterns.append(("GrandCab", grandcrab_pattern))

    TeslaCrypt_pattern = nx.DiGraph()
    TeslaCrypt_pattern.add_edges_from([
        ("set","InitializeCriticalSection"),
        ("set","EnterCriticalSection"),
        ("set", "WriteFile"),
        ("set", "CloseHandle"),
        ("set","VirtualQuery"),
        ("set","VirtualProtect"),
        ("set","DeleteObject"),
        ("set","DispatchMessageA"), #splash screen
        ("set","ShowWindow") #splash screen
    ])
    base_patterns.append(("Teslacrypt", TeslaCrypt_pattern))
    
    # Add more patterns as needed
    return base_patterns

# Find subgraph isomorphisms between base patterns and the target graph
def find_subgraph_isomorphisms(base_patterns, target_graph):
    target_nodes = set(target_graph.nodes())
    
    for pattern_name, base_graph in base_patterns:
        base_nodes = set(base_graph.nodes())
        
        # Check if there's at least one common node
        common_nodes = target_nodes.intersection(base_nodes)
        if len(common_nodes) < 5:
            print(f"No common nodes found between {pattern_name} pattern and target graph or too few common nodes to be isomorphic. Skipping...")
            continue
        
        print(f"Checking for {pattern_name} pattern with common nodes: {common_nodes}...")
        GM = isomorphism.DiGraphMatcher(target_graph, base_graph)
        if GM.subgraph_is_isomorphic():
            print(f"Isomorphic subgraph found for {pattern_name}!")
        else:
            print(f"No isomorphic subgraph found for {pattern_name}.")

# Main function to generate signatures
def generate_signatures(binary_file, json_file_path):
    file_hash = get_file_hash(binary_file)
    print(f"File MD5 Hash: {file_hash}")

    # Load CSV data
    csv_data = pd.read_csv(csv_path)

    # Check if the hash is in the CSV file using KMP algorithm
    csv_hashes = csv_data['hash'].astype(str).tolist()
    print(f"Total Hashes: {len(csv_hashes)}")
    spinner.white.bold.shark.on_blue.start()
    flag = 0
    print("\n")
    for _, row in csv_data.iterrows():
        if kmp_search(file_hash, row['hash']):
            print(f"Match found in CSV: {row['hash']} corresponds to {row['name']}")
            flag = 1
            spinner.stop()
            continue
    if flag!=1:
        print("No match found in CSV. Proceeding with CFG analysis.")
        spinner.stop()

    ghidra_headless_command = [
    'D:\\ghidra_11.0.1_PUBLIC\\support\\analyzeHeadless.bat',
    'D:\\ghidra_projects',
    'ransom2',
    '-import', f"{binary_file}",
    '-scriptPath', 'C:\\Users\\LENOVO\\ghidra_scripts',
    '-postScript', 'NewScript.py'
    ]

    subprocess.run(ghidra_headless_command)
    # Load the target graph from the JSON file
    target_graph = load_ransomware_graph(json_file_path)
    
    # Get base ransomware patterns
    base_patterns = get_base_ransomware_patterns()
    
    # Find subgraph isomorphisms
    find_subgraph_isomorphisms(base_patterns, target_graph)

# Command-line interface setup
def main():
    parser = argparse.ArgumentParser(description="Automatically generate string signatures of malware from binary files.")
    parser.add_argument('file', help="Path to the binary file.")
    parser.add_argument('json_file', help="Path to the JSON file containing the ransomware graph.")
    args = parser.parse_args()

    
    generate_signatures(args.file, args.json_file)

if __name__ == "__main__":
    main()

