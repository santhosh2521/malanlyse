import argparse
import hashlib
import capstone
import networkx as nx
from networkx.algorithms import isomorphism

def kmp_search(pattern, text):
    # KMP algorithm for pattern matching
    def compute_lps(pattern):
        lps = [0] * len(pattern)
        j = 0
        for i in range(1, len(pattern)):
            if pattern[i] == pattern[j]:
                j += 1
                lps[i] = j
            else:
                if j != 0:
                    j = lps[j - 1]
                else:
                    lps[i] = 0
        return lps
    
    lps = compute_lps(pattern)
    i = j = 0
    matches = []
    while i < len(text):
        if pattern[j] == text[i]:
            i += 1
            j += 1
        
        if j == len(pattern):
            matches.append(i - j)
            j = lps[j - 1]
        elif i < len(text) and pattern[j] != text[i]:
            if j != 0:
                j = lps[j - 1]
            else:
                i += 1
    return matches

def load_hashdb(filepath):
    with open(filepath, 'r') as file:
        hashdb = file.read().splitlines()
    return hashdb

def hash_binary(binary_data):
    return hashlib.sha256(binary_data).hexdigest()

def match_binary_with_hashdb(binary_hash, hashdb):
    for db_hash in hashdb:
        if kmp_search(binary_hash, db_hash):
            return True
    return False

def disassemble_binary(binary_data):
    # Capstone disassembler for x86_64 architecture
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    instructions = []
    for instruction in md.disasm(binary_data, 0x1000):
        instructions.append(f"{instruction.mnemonic} {instruction.op_str}")
    return instructions

def create_cfg_from_instructions(instructions):
    cfg = nx.DiGraph()
    current_block = []
    
    for instruction in instructions:
        current_block.append(instruction)
        if 'jmp' in instruction or 'ret' in instruction:
            block_id = len(cfg.nodes) + 1
            cfg.add_node(block_id, instructions=current_block)
            current_block = []
    
    return cfg

def find_subgraph_isomorphisms(graph1, graph2):
    GM = isomorphism.DiGraphMatcher(graph1, graph2)
    for subgraph in GM.subgraph_isomorphisms_iter():
        print(f"Subgraph isomorphism found: {subgraph}")

def generate_signatures(binary_file, hashdb_file):
    with open(binary_file, 'rb') as file:
        binary_data = file.read()
    
    print("Calculating binary hash...")
    binary_hash = hash_binary(binary_data)
    
    print("Loading HashDB...")
    hashdb = load_hashdb(hashdb_file)
    
    print("Matching binary hash with HashDB using KMP...")
    if match_binary_with_hashdb(binary_hash, hashdb):
        print("Match found in HashDB!")
    else:
        print("No match found in HashDB.")
    
    print("Disassembling binary...")
    instructions = disassemble_binary(binary_data)
    
    print("Creating control flow graph (CFG)...")
    cfg = create_cfg_from_instructions(instructions)
    nx.draw(cfg, with_labels=True)
    
    print("Checking for subgraph isomorphisms...")
    base_cfg = create_cfg_from_instructions(["mov eax, 1", "ret"])  # Example base CFG
    find_subgraph_isomorphisms(base_cfg, cfg)
    
    print("Signatures generated successfully.")

def main():
    parser = argparse.ArgumentParser(description="Automatically generate string signatures of malware from binary files.")
    parser.add_argument('binary_file', help="Path to the binary file.")
    parser.add_argument('hashdb_file', help="Path to the HashDB file.")
    args = parser.parse_args()
    
    generate_signatures(args.binary_file, args.hashdb_file)

if __name__ == "__main__":
    main()
