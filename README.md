# Malware Binary Analysis CLI Tool

Topic : Automatic generation of string signatures for malware detection

This CLI tool automates the process of analyzing malware binary files. It allows you to download a database of malware hashes, compute the MD5 hash of a binary file, and perform signature generation and control flow graph (CFG) analysis to identify potential ransomware patterns.


## Features

- **Download HashDB**: Automatically download a database of malware hashes.
- **MD5 Hash Calculation**: Compute the MD5 hash of a given binary file.
- **CFG Analysis**: Analyze the control flow graph (CFG) of a binary file to detect ransomware patterns.
- **Signature Matching**: Match the binary file hash against a local CSV database of malware hashes.
- **Subgraph Isomorphism Detection**: Identify if the binary contains isomorphic subgraphs corresponding to known ransomware patterns.


## Installation

### Prerequisites

- Python 3.x
- Ghidra (for CFG analysis)
- Required Python packages: `requests`, `argparse`, `os`, `hashlib`, `sqlite3`, `networkx`, `pandas`, `json`, `tqdm`, `yaspin`

### Setup

1. Clone the repository:
    ```bash
    git clone https://github.com/santhosh2521/malanlyse.git
    ```
    ```bash
    cd malanlyse
    ```

2. Install the required Python packages
   

## Usage

To analyze a binary file and generate signatures, use the following command:

```bash
python <script-name>.py <path-to-binary-file> <path-to-json-file>
```
Example:

```bash
python el2.2.py sample_binary.exe ransomware_graph.json
```

This command will:

- Compute the MD5 hash of `sample_binary.exe`.
- Compare the hash with entries in the HashDB.
- If no match is found, it will proceed with CFG analysis using Ghidra.
- Load a ransomware graph from `ransomware_graph.json`.
- Attempt to find subgraph isomorphisms between known ransomware patterns and the target binary.


## Additional Notes

- Ensure that Ghidra is installed and the `ghidra_headless_command` is correctly configured in the script.
- The ransomware patterns are hardcoded in the script and include WannaCry, GrandCrab, and TeslaCrypt.


## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss any changes.


## Acknowledgments

This tool uses the [MalwareHashDB](https://github.com/CYB3RMX/MalwareHashDB) for hash matching.


