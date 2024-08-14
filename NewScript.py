from ghidra.util.graph import DirectedGraph
from ghidra.util.graph import Edge
from ghidra.util.graph import Vertex
from java.io import FileWriter
import json

# Define a list of ransomware-related API calls
ransomware_behaviors = [
    "InitializeCriticalSection","GetProcAddress","CreateFileA","CreateProcessA" "WriteFile", "GetFileSizeEx", "OpenProcess", 
    "VirtualAlloc", "WriteProcessMemory", "RegCreateKeyW","RegQueryValueExA", 
    "RegSetValue","RegCloseKey","setCurrentDirectoryW","GetCurrentDirectoryA","GetComputerNameW",
    "GlobalFree","GlobalAlloc","DeleteCriticalSection","CryptReleaseContext","GetFileSize","ReadFile",
    "EnterCriticalSection","LeaveCriticalSection","SetFileAttributesW","GetWindowsDirectoryW","GetTempPathW",
    "OpenSCManagerA","OpenServiceA","CreateServiceA","StartServiceA","CloseServiceHandle","FindResourceA","LoadResource",
    "LockResource","SizeofResource","OpenMutexA","GetModuleHandleA","VirtualProtect","CloseHandle","PulseEvent",
    "WriteFileGather","FlushFileBuffers","VirtualLock","IsDebuggerPresent",
    "FlushViewOfFile","EncryptFileW","GetSecurityDescriptorDacl","VirtualQuery","InterlockedExchange","DeleteObject","DispatchMessageA",
    "ShowWindow","GetUserNameExA","OpenClipboard","OutputDebugStringA",
    "GetPrivateProfileString","EmptyClipboard","PathRemoveExtensionW","WaitForDebugEvent"
]

def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

# Initialize directed graph
digraph = DirectedGraph()
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

# Dictionary to store the graph
graph_dict = {"nodes": [], "edges": []}

funcs = fm.getFunctions(True) # True means iterate forward
for func in funcs: 
    # Add function vertices
    func_name = "{} @ 0x{}".format(func.getName(), func.getEntryPoint())
    vertex = Vertex(func)
    digraph.add(vertex)
    
    # Store the vertex in the graph dictionary
    graph_dict["nodes"].append(func_name)
    
    # Add edges for suspicious ransomware behavior calls
    entryPoint = func.getEntryPoint()
    instructions = listing.getInstructions(entryPoint, True)
    for instruction in instructions:
        addr = instruction.getAddress()
        oper = instruction.getMnemonicString()
        if oper == "CALL":
            flows = instruction.getFlows()
            if len(flows) == 1:
                target_addr = flows[0]
                target_func = fm.getFunctionAt(target_addr)
                
                if target_func:
                    target_func_name = target_func.getName()
                    
                    # Check if the function name matches ransomware-related behavior
                    if any(behavior in target_func_name for behavior in ransomware_behaviors):
                        dll_name = target_func_name.split(".dll")[0].upper() if target_func_name.endswith("dll") else "N/A"
                        target_func_name = "{} @ 0x{}".format(target_func.getName(), target_func.getEntryPoint())
                        digraph.add(Edge(vertex, Vertex(target_func)))
                        
                        # Store the edge in the graph dictionary with DLL type and behavior hint
                        graph_dict["edges"].append({
                            "from": func.getName(), 
                            "to": target_func.getName(),
                        })

# Print DiGraph info (optional)
print("DiGraph info:")
edges = digraph.edgeIterator()
while edges.hasNext():
    edge = edges.next()
    from_vertex = edge.from()
    to_vertex = edge.to()
    print("  Edge from {} to {}".format(from_vertex, to_vertex))

vertices = digraph.vertexIterator()
while vertices.hasNext():
    vertex = vertices.next()
    print("  Vertex: {} (key: {})".format(vertex, vertex.key()))

# Save the graph to a JSON file
output_path = "D:\\dms_daa_el\\ransomware_graph.json"
try:
    json_data = json.dumps(graph_dict, indent=4)  # Convert the dictionary to a JSON string with indentation
    writer = FileWriter(output_path)
    writer.write(json_data)
    writer.close()
    print("Graph saved to {}".format(output_path))
except Exception as e:
    print("Failed to save graph: {}".format(e))