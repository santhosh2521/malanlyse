import argparse
import requests
import os
import hashlib
import sqlite3
from tqdm import tqdm
import networkx as nx
import capstone
import pefile

# Setup paths and variables
install_dir = os.path.join(os.getcwd(), "sc0pe_Base")
db_url = "https://raw.githubusercontent.com/CYB3RMX/MalwareHashDB/main/HashDB"
db_path = os.path.join(install_dir, "HashDB")

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

# Hashing the binary file using SHA-256
# Hashing the binary file using MD5
def get_file_hash(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# Detect architecture and mode using Capstone and PEfile
def detect_arch_and_mode(binary_data):
    try:
        pe = pefile.PE(data=binary_data)
        if pe.FILE_HEADER.Machine == 0x14c:  # IMAGE_FILE_MACHINE_I386
            return capstone.CS_ARCH_X86, capstone.CS_MODE_32
        elif pe.FILE_HEADER.Machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
            return capstone.CS_ARCH_X86, capstone.CS_MODE_64
    except pefile.PEFormatError:
        # Handle other binary formats (e.g., ELF, Mach-O)
        print("Non-PE file format detected or PE parsing failed.")
    # Default fallback
    return capstone.CS_ARCH_X86, capstone.CS_MODE_64

# Disassemble binary file using Capstone
def disassemble_binary(binary_data):
    arch, mode = detect_arch_and_mode(binary_data)
    md = capstone.Cs(arch, mode)
    instructions = []
    for instruction in md.disasm(binary_data, 0x1000):
        instructions.append(f"{instruction.mnemonic} {instruction.op_str}")
    print(instructions)
    return instructions

# Create a CFG from the disassembled instructions
def create_cfg_from_instructions(instructions):
    cfg = nx.DiGraph()
    current_block = []
    block_id = 0

    for instruction in instructions:
        current_block.append(instruction)
        if any(op in instruction for op in ['jmp', 'ret', 'call', 'je', 'jne', 'jg', 'jge', 'jl', 'jle']):
            block_id += 1
            cfg.add_node(block_id, instructions=current_block)
            if block_id > 1:
                cfg.add_edge(block_id - 1, block_id)
            current_block = []

    if current_block:  # Add remaining instructions as the last block
        block_id += 1
        cfg.add_node(block_id, instructions=current_block)
        if block_id > 1:
            cfg.add_edge(block_id - 1, block_id)

    return cfg

# Find subgraph isomorphisms between graphs
def find_subgraph_isomorphisms(graph1, graph2):
    GM = nx.isomorphism.DiGraphMatcher(graph1, graph2)
    for subgraph in GM.subgraph_isomorphisms_iter():
        print(f"Subgraph isomorphism found: {subgraph}")
        for node in subgraph:
            print(f"Base CFG node {node}: {graph1.nodes[node]['instructions']}")
            print(f"Isomorphic CFG node {subgraph[node]}: {graph2.nodes[subgraph[node]]['instructions']}")

# Main function to generate signatures
def generate_signatures(binary_file):
    conn = check_db()
    cursor = conn.cursor()
    file_hash = get_file_hash(binary_file)

    if not file_hash:
        print("Error: Could not generate hash for the file.")
        return

    print(f"File SHA-256 Hash: {file_hash}")

    cursor.execute("SELECT * FROM HashDB WHERE hash=?", (file_hash,))
    hash_entry = cursor.fetchone()

    if hash_entry:
        print(f"Match found in HashDB: {hash_entry}")
    else:
        print("No match found in HashDB. Proceeding with disassembly and CFG generation.")

    try:
        with open(binary_file, 'rb') as f:
            binary_data = f.read()

        print("Disassembling binary...")
        instructions = disassemble_binary(binary_data)

        print("Creating control flow graph (CFG)...")
        cfg = create_cfg_from_instructions(instructions)

        base_cfgs = [
            # Example base CFGs for pattern matching, updated as needed
            ["mov eax, offset file_name", "call CreateFile", "mov eax, offset buffer", "call ReadFile", 
             "call AES_encrypt", "call RSA_encrypt", "call WriteFile", "call CloseHandle"],
            ["call InternetOpen", "call InternetConnect", "call HttpSendRequest", "mov eax, offset file_name", 
             "call CreateFile", "mov eax, offset buffer", "call ReadFile", "call Salsa20_encrypt"],
        ]
        
        for index, base_instructions in enumerate(base_cfgs):
            base_cfg = create_cfg_from_instructions(base_instructions)
            print(f"Checking for subgraph isomorphisms with base CFG {index + 1}...")
            find_subgraph_isomorphisms(base_cfg, cfg)
    except Exception as e:
        print(f"Error during analysis: {e}")

    conn.close()

# Command-line interface setup
def main():
    parser = argparse.ArgumentParser(description="Automatically generate string signatures of malware from binary files.")
    parser.add_argument('file', help="Path to the binary file.")
    args = parser.parse_args()

    generate_signatures(args.file)

if __name__ == "__main__":
    main()
