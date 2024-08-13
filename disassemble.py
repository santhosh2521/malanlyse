import argparse
import requests
import os
import hashlib
import sqlite3
from tqdm import tqdm
import networkx as nx
from networkx.algorithms import isomorphism
import subprocess
import pefile
import pandas as pd


# Setup paths and variables
install_dir = f"D:\\dms_daa_el\\sc0pe_Base"
db_url = "https://raw.githubusercontent.com/CYB3RMX/MalwareHashDB/main/HashDB"
db_path = f"{install_dir}/HashDB"
csv_path = f"HashDB.csv"
ghidra_headless_path = "C:\\Path\\To\\Ghidra\\support\\analyzeHeadless.bat"
project_path = "C:\\Path\\To\\GhidraProject"
project_name = "MyGhidraProject"

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

# Disassemble binary file using Ghidra
def disassemble_binary(binary_file):
    output_file = os.path.join(install_dir, "disassembled.txt")
    command = [
        ghidra_headless_path,
        project_path,
        project_name,
        "-import", binary_file,
        "-postScript", "ExtractDisassembly.py",
        "-deleteProject",
        "-scriptPath", os.path.dirname(os.path.abspath(__file__)),
        "-outputFile", output_file
    ]
    subprocess.run(command, check=True)
    
    with open(output_file, 'r') as f:
        instructions = f.readlines()

    print(instructions)
    return instructions

# Create a CFG from the disassembled instructions
def create_cfg_from_instructions(instructions):
    cfg = nx.DiGraph()
    current_block = []
    
    for instruction in instructions:
        current_block.append(instruction.strip())
        if 'jmp' in instruction or 'ret' in instruction:
            block_id = len(cfg.nodes) + 1
            cfg.add_node(block_id, instructions=current_block)
            current_block = []
    print(cfg)
    return cfg

# Find subgraph isomorphisms between graphs
def find_subgraph_isomorphisms(graph1, graph2):
    GM = isomorphism.DiGraphMatcher(graph1, graph2)
    for subgraph in GM.subgraph_isomorphisms_iter():
        print(f"Subgraph isomorphism found: {subgraph}")
        for node in subgraph:
            print(f"Base CFG node {node}: {graph1.nodes[node]['instructions']}")
            print(f"Isomorphic CFG node {subgraph[node]}: {graph2.nodes[subgraph[node]]['instructions']}")

# Main function to generate signatures
def generate_signatures(binary_file):
    ret = 0
    file_hash = get_file_hash(binary_file)
    print(f"File MD5 Hash: {file_hash}")
    # Load CSV data
    csv_data = pd.read_csv(csv_path)

    # Check if the hash is in the CSV file using KMP algorithm
    csv_hashes = csv_data['hash'].astype(str).tolist()

    print(f"Total Hashes: {len(csv_hashes)}")
    for _, row in csv_data.iterrows():
        if kmp_search(file_hash, row['hash']):
            print(f"Match found in CSV: {row['hash']} corresponds to {row['name']}")
            continue
    else:
        print("No match found in CSV. Proceeding with disassembly and CFG generation.")

    print("Disassembling binary...")
    instructions = disassemble_binary(binary_file)

    print("Creating control flow graph (CFG)...")
    cfg = create_cfg_from_instructions(instructions)
    base_cfgs = [
        # Example CFGs for ransomware patterns
        ["mov eax, offset file_name", "call CreateFile", "mov eax, offset buffer", "call ReadFile", 
        "call AES_encrypt", "call RSA_encrypt", "call WriteFile", "call CloseHandle", "jmp start", 
        "xor eax, eax", "xor ecx, ecx"],

        ["call InternetOpen", "call InternetConnect", "call HttpSendRequest", "mov eax, offset file_name", 
        "call CreateFile", "mov eax, offset buffer", "call ReadFile", "call Salsa20_encrypt", 
        "call WriteFile", "call CloseHandle", "jmp start", "pushad", "pushfd", "call UnpackRoutine"],

        ["call GetMBR", "call EncryptMBR", "mov eax, offset file_name", "call CreateFile", 
        "mov eax, offset buffer", "call ReadFile", "call AES_encrypt", "call WriteFile", 
        "call CloseHandle", "call LockSystem", "mov eax, EncodedShellcode", "call DecodeShellcode"],

        ["call InternetOpen", "call InternetConnect", "mov eax, offset file_name", "call CreateFile", 
        "mov eax, offset buffer", "call ReadFile", "call Custom_encrypt", "call WriteFile", 
        "call CloseHandle", "call SendRansomNote", "call CheckDebugger", "cmp eax, 0", 
        "jne SkipEncryption", "call EncryptFiles"],
    ]

    for index, instructions in enumerate(base_cfgs):
        base_cfg = create_cfg_from_instructions(instructions)
        print(f"Checking for subgraph isomorphisms with base CFG {index + 1}...")
        find_subgraph_isomorphisms(base_cfg, cfg)

# Command-line interface setup
def main():
    parser = argparse.ArgumentParser(description="Automatically generate string signatures of malware from binary files.")
    parser.add_argument('file', help="
