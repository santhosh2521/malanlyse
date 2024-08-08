import argparse
import requests
import os
import hashlib
import sqlite3
from tqdm import tqdm
from networkx.algorithms import isomorphism
import networkx as nx
import capstone
import pefile

# Setup paths and variables
install_dir = f"D:\dms_daa_el\sc0pe_Base"
db_url = "https://raw.githubusercontent.com/CYB3RMX/MalwareHashDB/main/HashDB"
db_path = f"{install_dir}/HashDB"

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
            print(f"Pattern found at index {i - j}")
            j = lps[j - 1]
        elif i < len(text) and pattern[j] != text[i]:
            if j != 0:
                j = lps[j - 1]
            else:
                i += 1

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
def detect_arch_and_mode(binary_data):
    try:
        pe = pefile.PE(data=binary_data)
        if pe.FILE_HEADER.Machine == 0x14c:  # IMAGE_FILE_MACHINE_I386
            return capstone.CS_ARCH_X86, capstone.CS_MODE_32
        elif pe.FILE_HEADER.Machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
            return capstone.CS_ARCH_X86, capstone.CS_MODE_64
    except pefile.PEFormatError:
        # Default to x86_64 if PE parsing fails
        return capstone.CS_ARCH_X86, capstone.CS_MODE_64
# Disassemble binary file using Capstone
def disassemble_binary(binary_data):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    instructions = []
    for instruction in md.disasm(binary_data, 0x1000):
        instructions.append(f"{instruction.mnemonic} {instruction.op_str}")
    print(instructions)
    return instructions

# Create a CFG from the disassembled instructions
def create_cfg_from_instructions(instructions):
    cfg = nx.DiGraph()
    current_block = []
    
    for instruction in instructions:
        current_block.append(instruction)
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
    conn = sqlite3.connect(f"{db_path}")
    cursor = conn.cursor()
    file_hash = get_file_hash(binary_file)
    print(f"File MD5 Hash: {file_hash}")

    database_content = cursor.execute(f"SELECT * FROM HashDB").fetchall()

    print(f"Total Hashes: {len(database_content)}")

    cursor.execute("SELECT * FROM HashDB WHERE hash=?", (file_hash,))
    hash_entry = cursor.fetchone()

    if hash_entry:
        print(f"Match found in HashDB: {hash_entry}")
        
    else:
        print("No match found in HashDB. Proceeding with disassembly and CFG generation.")

    with open(binary_file, 'rb') as f:
        binary_data = f.read()

    print("Disassembling binary...")
    instructions = disassemble_binary(binary_data)
        
    print("Creating control flow graph (CFG)...")
    cfg = create_cfg_from_instructions(instructions)
    base_cfgs = [
    # WannaCry pattern with potential obfuscation
    ["mov eax, offset file_name", "call CreateFile", "mov eax, offset buffer", "call ReadFile", 
     "call AES_encrypt", "call RSA_encrypt", "call WriteFile", "call CloseHandle", "jmp start", 
     "xor eax, eax", "xor ecx, ecx"],  # Obfuscation
    
    # GrandCrab pattern with packer detection
    ["call InternetOpen", "call InternetConnect", "call HttpSendRequest", "mov eax, offset file_name", 
     "call CreateFile", "mov eax, offset buffer", "call ReadFile", "call Salsa20_encrypt", 
     "call WriteFile", "call CloseHandle", "jmp start", "pushad", "pushfd", "call UnpackRoutine"],  # Packer
    
    # Petya pattern with potential crypter
    ["call GetMBR", "call EncryptMBR", "mov eax, offset file_name", "call CreateFile", 
     "mov eax, offset buffer", "call ReadFile", "call AES_encrypt", "call WriteFile", 
     "call CloseHandle", "call LockSystem", "mov eax, EncodedShellcode", "call DecodeShellcode"],  # Crypter
    
    # LockBit pattern with anti-debugging techniques
    ["call InternetOpen", "call InternetConnect", "mov eax, offset file_name", "call CreateFile", 
     "mov eax, offset buffer", "call ReadFile", "call Custom_encrypt", "call WriteFile", 
     "call CloseHandle", "call SendRansomNote", "call CheckDebugger", "cmp eax, 0", 
     "jne SkipEncryption", "call EncryptFiles"],  # Anti-Debugging
]
    
    for index, instructions in enumerate(base_cfgs):
        base_cfg = create_cfg_from_instructions(instructions)
        print(f"Checking for subgraph isomorphisms with base CFG {index + 1}...")
        find_subgraph_isomorphisms(base_cfg, cfg)
    
    conn.close()
    

# Command-line interface setup
def main():
    parser = argparse.ArgumentParser(description="Automatically generate string signatures of malware from binary files.")
    parser.add_argument('file', help="Path to the binary file.")
    args = parser.parse_args()
    
    generate_signatures(args.file)

if __name__ == "__main__":
    main()
