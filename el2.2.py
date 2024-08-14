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

 
install_dir = f"sc0pe_Base"
db_url = "https://raw.githubusercontent.com/CYB3RMX/MalwareHashDB/main/HashDB"
db_path = f"{install_dir}/HashDB"
csv_path = f"HashDB.csv"
spinner = yaspin()


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


def check_db():
    if not os.path.isfile(db_path):
        download_db()
    return sqlite3.connect(db_path)


def get_file_hash(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


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
            return True  
            j = lps[j - 1]
        elif i < len(text) and pattern[j] != text[i]:
            if j != 0:
                j = lps[j - 1]
            else:
                i += 1

    return False  

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


def load_ransomware_graph(json_file_path):
    with open(json_file_path, 'r') as file:
        graph_data = json.load(file)
    
    graph = nx.DiGraph()
    graph.add_edges_from((edge['from'], edge['to']) for edge in graph_data['edges'])
    return graph


def get_base_ransomware_patterns():
    base_patterns = []
    

    wannacry_pattern = nx.DiGraph()
    wannacry_pattern.add_edges_from([
        ("set","InitializeCriticalSection"),
        ("set","LeaveCriticalSection"),
        ("set","EnterCriticalSection"),
        ("set", "WriteFile"),
        ("set", "CloseHandle"),
        ("set","RegCreateKeyW"),
        ("set","CryptReleaseContext"),#encrypting
        ("set","OpenServiceA"),
        ("set","StartServiceA"),
        ("set","LoadResource"),
        ("set","LockResource"),
        ("set","WNetAddConnection2A")
    ])
    base_patterns.append(("WannaCry1", wannacry_pattern))
    
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
        ("set","IsDebuggerPresent")#anti debugging
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
    

    return base_patterns


def find_subgraph_isomorphisms(base_patterns, target_graph):
    target_nodes = set(target_graph.nodes())
    
    for pattern_name, base_graph in base_patterns:
        base_nodes = set(base_graph.nodes())
        

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


def generate_signatures(binary_file, json_file_path):
    file_hash = get_file_hash(binary_file)
    print(f"File MD5 Hash: {file_hash}")


    csv_data = pd.read_csv(csv_path)


    csv_hashes = csv_data['hash'].astype(str).tolist()
    print(f"Total Hashes: {len(csv_hashes)}")
    spinner.white.bold.shark.on_blue.start()
    flag = 0
    print("\n")
    for _, row in csv_data.iterrows():
        if kmp_search(file_hash, row['hash']):
            print(f"Match found in CSV: {row['hash']} corresponds to {row['name']}")
            flag = 1
            continue
    if flag!=1:
        print("No match found in CSV. Proceeding with CFG analysis.")

    spinner.stop()

    ghidra_headless_command = [
    '<path to your ghidra headless batch file>',
    '<path to your ghidra project>',
    '<project name>',
    '-import', f"{binary_file}",
    '-scriptPath', '<path to your script>',
    '-postScript', '<script_name>'
    ]
    spinner.white.bold.shark.on_blue.start()
    subprocess.run(ghidra_headless_command)
    spinner.stop()

    target_graph = load_ransomware_graph(json_file_path)
    

    base_patterns = get_base_ransomware_patterns()
    

    find_subgraph_isomorphisms(base_patterns, target_graph)


def main():
    parser = argparse.ArgumentParser(description="Automatically generate string signatures of malware from binary files.")
    parser.add_argument('file', help="Path to the binary file.")
    parser.add_argument('json_file', help="Path to the JSON file containing the ransomware graph.")
    args = parser.parse_args()

    
    generate_signatures(args.file, args.json_file)

if __name__ == "__main__":
    main()