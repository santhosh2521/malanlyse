#SSCRIPT 1

# from ghidra.util.graph import DirectedGraph
# from ghidra.util.graph import Edge
# from ghidra.util.graph import Vertex
# from java.io import FileWriter
# import json

# def getAddress(offset):
#     return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

# # Initialize directed graph
# digraph = DirectedGraph()
# listing = currentProgram.getListing()
# fm = currentProgram.getFunctionManager()

# # Dictionary to store the graph
# graph_dict = {"nodes": [], "edges": []}

# funcs = fm.getFunctions(True) # True means iterate forward
# for func in funcs: 
#     # Add function vertices
#     func_name = "{} @ 0x{}".format(func.getName(), func.getEntryPoint())
#     print("Function: {}".format(func_name)) # FunctionDB
#     vertex = Vertex(func)
#     digraph.add(vertex)
    
#     # Store the vertex in the graph dictionary
#     graph_dict["nodes"].append(func_name)
    
#     # Add edges for static calls
#     entryPoint = func.getEntryPoint()
#     instructions = listing.getInstructions(entryPoint, True)
#     for instruction in instructions:
#         addr = instruction.getAddress()
#         oper = instruction.getMnemonicString()
#         if oper == "CALL":
#             print("    0x{} : {}".format(addr, instruction))
#             flows = instruction.getFlows()
#             if len(flows) == 1:
#                 target_addr = "0x{}".format(flows[0])
#             if getAddress(target_addr):
#                 target_func = fm.getFunctionAt(getAddress(target_addr))
#                 target_func_name = "{} @ 0x{}".format(target_func.getName(), target_func.getEntryPoint())
#                 digraph.add(Edge(vertex, Vertex(target_func)))
                
#                 # Store the edge in the graph dictionary
#                 graph_dict["edges"].append({"from": func_name, "to": target_func_name})

# # Print DiGraph info (optional)
# print("DiGraph info:")
# edges = digraph.edgeIterator()
# while edges.hasNext():
#     edge = edges.next()
#     from_vertex = edge.from()
#     to_vertex = edge.to()
#     print("  Edge from {} to {}".format(from_vertex, to_vertex))

# vertices = digraph.vertexIterator()
# while vertices.hasNext():
#     vertex = vertices.next()
#     print("  Vertex: {} (key: {})".format(vertex, vertex.key()))

# # Save the graph to a JSON file
# output_path = "D:\\dms_daa_el\\graph.json"
# try:
#     json_data = json.dumps(graph_dict)  # Convert the dictionary to a JSON string
#     writer = FileWriter(output_path)
#     writer.write(json_data)
#     writer.close()
#     print("Graph saved to {}".format(output_path))
# except Exception as e:
#     print("Failed to save graph: {}".format(e))


#SCRIPT 2
# from ghidra.util.graph import DirectedGraph
# from ghidra.util.graph import Edge
# from ghidra.util.graph import Vertex
# from java.io import FileWriter
# import json

# def getAddress(offset):
#     return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

# # Initialize directed graph
# digraph = DirectedGraph()
# listing = currentProgram.getListing()
# fm = currentProgram.getFunctionManager()

# # Dictionary to store the graph
# graph_dict = {"nodes": [], "edges": []}

# funcs = fm.getFunctions(True)  # True means iterate forward
# for func in funcs: 
#     # Add function vertices
#     func_name = "{} @ 0x{}".format(func.getName(), func.getEntryPoint())
#     print("Function: {}".format(func_name))  # FunctionDB
#     vertex = Vertex(func)
#     digraph.add(vertex)
    
#     # Store the vertex in the graph dictionary
#     graph_dict["nodes"].append(func_name)
    
#     # Add edges based on instruction contents
#     entryPoint = func.getEntryPoint()
#     instructions = listing.getInstructions(entryPoint, True)
#     prev_instruction = None
#     for instruction in instructions:
#         addr = instruction.getAddress()
#         oper = instruction.getMnemonicString()
#         print("    0x{} : {}".format(addr, instruction))
        
#         if prev_instruction:
#             # Use the content of instructions as edges
#             from_vertex = Vertex(prev_instruction)
#             to_vertex = Vertex(instruction)
#             digraph.add(Edge(from_vertex, to_vertex))
            
#             # Store the edge in the graph dictionary
#             graph_dict["edges"].append({
#                 "from": "0x{}".format(prev_instruction.getAddress()),
#                 "to": "0x{}".format(instruction.getAddress()),
#                 "content": "{} -> {}".format(prev_instruction, instruction)
#             })
        
#         prev_instruction = instruction

# # Print DiGraph info (optional)
# print("DiGraph info:")
# edges = digraph.edgeIterator()
# while edges.hasNext():
#     edge = edges.next()
#     from_vertex = edge.from()
#     to_vertex = edge.to()
#     print("  Edge from {} to {}".format(from_vertex, to_vertex))

# vertices = digraph.vertexIterator()
# while vertices.hasNext():
#     vertex = vertices.next()
#     print("  Vertex: {} (key: {})".format(vertex, vertex.key()))

# # Save the graph to a JSON file
# output_path = "D:\\dms_daa_el\\graph.json"
# try:
#     json_data = json.dumps(graph_dict)  # Convert the dictionary to a JSON string
#     writer = FileWriter(output_path)
#     writer.write(json_data)
#     writer.close()
#     print("Graph saved to {}".format(output_path))
# except Exception as e:
#     print("Failed to save graph: {}".format(e))



#SCRIPT 3
# from ghidra.util.graph import DirectedGraph
# from ghidra.util.graph import Edge
# from ghidra.util.graph import Vertex
# from java.io import FileWriter
# import json

# # Define a list of ransomware-related API calls
# ransomware_behaviors = [
#     "CreateFile", "WriteFile", "EncryptFile", "OpenProcess", 
#     "VirtualAlloc", "WriteProcessMemory", "RegCreateKey", 
#     "RegSetValue", "SetFileAttributes", "DeleteFile", "MoveFile", 
#     "InternetOpen", "InternetConnect", "HttpSendRequest"
# ]

# def getAddress(offset):
#     return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

# # Initialize directed graph
# digraph = DirectedGraph()
# listing = currentProgram.getListing()
# fm = currentProgram.getFunctionManager()

# # Dictionary to store the graph
# graph_dict = {"nodes": [], "edges": []}

# funcs = fm.getFunctions(True) # True means iterate forward
# for func in funcs: 
#     # Add function vertices
#     func_name = "{} @ 0x{}".format(func.getName(), func.getEntryPoint())
#     vertex = Vertex(func)
#     digraph.add(vertex)
    
#     # Store the vertex in the graph dictionary
#     graph_dict["nodes"].append(func_name)
    
#     # Add edges for suspicious ransomware behavior calls
#     entryPoint = func.getEntryPoint()
#     instructions = listing.getInstructions(entryPoint, True)
#     for instruction in instructions:
#         addr = instruction.getAddress()
#         oper = instruction.getMnemonicString()
#         if oper == "CALL":
#             flows = instruction.getFlows()
#             if len(flows) == 1:
#                 target_addr = flows[0]
#                 target_func = fm.getFunctionAt(target_addr)
                
#                 if target_func:
#                     target_func_name = target_func.getName()
                    
#                     # Check if the function name matches ransomware-related behavior
#                     if any(behavior in target_func_name for behavior in ransomware_behaviors):
#                         dll_name = target_func_name.split(".dll")[0].upper() if target_func_name.endswith("dll") else "N/A"
#                         target_func_name = "{} @ 0x{}".format(target_func.getName(), target_func.getEntryPoint())
#                         digraph.add(Edge(vertex, Vertex(target_func)))
                        
#                         # Store the edge in the graph dictionary with DLL type and behavior hint
#                         graph_dict["edges"].append({
#                             "from": func_name, 
#                             "to": target_func_name, 
#                             "dll": dll_name,
#                             "behavior": target_func_name
#                         })

# # Print DiGraph info (optional)
# print("DiGraph info:")
# edges = digraph.edgeIterator()
# while edges.hasNext():
#     edge = edges.next()
#     from_vertex = edge.from()
#     to_vertex = edge.to()
#     print("  Edge from {} to {}".format(from_vertex, to_vertex))

# vertices = digraph.vertexIterator()
# while vertices.hasNext():
#     vertex = vertices.next()
#     print("  Vertex: {} (key: {})".format(vertex, vertex.key()))

# # Save the graph to a JSON file
# output_path = "D:\\dms_daa_el\\ransomware_graph.json"
# try:
#     json_data = json.dumps(graph_dict, indent=4)  # Convert the dictionary to a JSON string with indentation
#     writer = FileWriter(output_path)
#     writer.write(json_data)
#     writer.close()
#     print("Graph saved to {}".format(output_path))
# except Exception as e:
#     print("Failed to save graph: {}".format(e))

#SCRIPT 4 with XOR
# from ghidra.util.graph import DirectedGraph
# from ghidra.util.graph import Edge
# from ghidra.util.graph import Vertex
# from java.io import FileWriter
# import json
# import re

# # Define a list of ransomware-related API calls
# ransomware_behaviors = [
#     "CreateFile", "WriteFile", "EncryptFile", "OpenProcess", 
#     "VirtualAlloc", "WriteProcessMemory", "RegCreateKey", 
#     "RegSetValue", "SetFileAttributes", "DeleteFile", "MoveFile", 
#     "InternetOpen", "InternetConnect", "HttpSendRequest"
# ]

# def getAddress(offset):
#     return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

# # Initialize directed graph
# digraph = DirectedGraph()
# listing = currentProgram.getListing()
# fm = currentProgram.getFunctionManager()

# # Dictionary to store the graph
# graph_dict = {"nodes": [], "edges": []}

# funcs = fm.getFunctions(True) # True means iterate forward
# for func in funcs: 
#     # Add function vertices
#     func_name = "{} @ 0x{}".format(func.getName(), func.getEntryPoint())
#     vertex = Vertex(func)
#     digraph.add(vertex)
    
#     # Store the vertex in the graph dictionary
#     graph_dict["nodes"].append(func_name)
    
#     # Add edges for suspicious ransomware behavior calls and XOR instructions
#     entryPoint = func.getEntryPoint()
#     instructions = listing.getInstructions(entryPoint, True)
#     for instruction in instructions:
#         addr = instruction.getAddress()
#         oper = instruction.getMnemonicString()
#         operands = instruction.getDefaultOperandRepresentation(0)

#         # Check for CALL instructions
#         if oper == "CALL":
#             # Handle CALL instructions with direct and indirect addressing
#             if "dword ptr" in operands:
#                 # Extract DLL and function name from indirect call
#                 match = re.search(r'->([^.]+)\.DLL::(\w+)', operands, re.IGNORECASE)
#                 if match:
#                     dll_name = match.group(1).upper()
#                     target_func_name = match.group(2)
#                     full_target_func_name = "{}::{}".format(dll_name, target_func_name)
                    
#                     # Check if the function name matches ransomware-related behavior
#                     if any(behavior in target_func_name for behavior in ransomware_behaviors):
#                         target_func_label = "{} @ [{}]".format(full_target_func_name, operands)
#                         digraph.add(Edge(vertex, Vertex(target_func_label)))
                        
#                         # Store the edge in the graph dictionary with DLL type and behavior hint
#                         graph_dict["edges"].append({
#                             "from": func_name, 
#                             "to": target_func_label, 
#                             "dll": dll_name,
#                             "behavior": target_func_name
#                         })
#             else:
#                 # Handle direct calls if present
#                 flows = instruction.getFlows()
#                 if len(flows) == 1:
#                     target_addr = flows[0]
#                     target_func = fm.getFunctionAt(target_addr)
                    
#                     if target_func:
#                         target_func_name = target_func.getName()
                        
#                         # Check if the function name matches ransomware-related behavior
#                         if any(behavior in target_func_name for behavior in ransomware_behaviors):
#                             dll_name = target_func_name.split(".dll")[0].upper() if target_func_name.endswith("dll") else "N/A"
#                             target_func_name = "{} @ 0x{}".format(target_func.getName(), target_func.getEntryPoint())
#                             digraph.add(Edge(vertex, Vertex(target_func)))
                            
#                             # Store the edge in the graph dictionary with DLL type and behavior hint
#                             graph_dict["edges"].append({
#                                 "from": func_name, 
#                                 "to": target_func_name, 
#                                 "dll": dll_name,
#                                 "behavior": target_func_name
#                             })

#         # Check for XOR instructions
#         elif oper == "XOR":
#             # Store the XOR instruction details in the graph dictionary
#             xor_detail = "XOR at 0x{}".format(addr)
#             graph_dict["edges"].append({
#                 "from": func_name, 
#                 "to": xor_detail,
#                 "behavior": "XOR instruction"
#             })
#             print("Found XOR instruction: {}".format(xor_detail))

# # Print DiGraph info (optional)
# print("DiGraph info:")
# edges = digraph.edgeIterator()
# while edges.hasNext():
#     edge = edges.next()
#     from_vertex = edge.from()
#     to_vertex = edge.to()
#     print("  Edge from {} to {}".format(from_vertex, to_vertex))

# vertices = digraph.vertexIterator()
# while vertices.hasNext():
#     vertex = vertices.next()
#     print("  Vertex: {} (key: {})".format(vertex, vertex.key()))

# # Save the graph to a JSON file
# output_path = "D:\\dms_daa_el\\ransomware_graph.json"
# try:
#     json_data = json.dumps(graph_dict, indent=4)  # Convert the dictionary to a JSON string with indentation
#     writer = FileWriter(output_path)
#     writer.write(json_data)
#     writer.close()
#     print("Graph saved to {}".format(output_path))
# except Exception as e:
#     print("Failed to save graph: {}".format(e))

#script 5
# from ghidra.util.graph import DirectedGraph
# from ghidra.util.graph import Edge
# from ghidra.util.graph import Vertex
# from java.io import FileWriter
# import json

# # Define a list of ransomware-related API calls
# ransomware_behaviors = [
#     "CreateFile", "WriteFile", "EncryptFile", "OpenProcess", 
#     "VirtualAlloc", "WriteProcessMemory", "RegCreateKey", 
#     "RegSetValue", "SetFileAttributes", "DeleteFile", "MoveFile", 
#     "InternetOpen", "InternetConnect", "HttpSendRequest","FUN_00407186","FUN_004023a0","FUN_004036b9","FUN_00402b46","FUN_00402de1",
#     "GetModuleFileNameA"
# ]

# def getAddress(offset):
#     return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

# # Initialize directed graph
# digraph = DirectedGraph()
# listing = currentProgram.getListing()
# fm = currentProgram.getFunctionManager()

# # Dictionary to store the graph
# graph_dict = {"nodes": [], "edges": []}

# funcs = fm.getFunctions(True) # True means iterate forward
# for func in funcs: 
#     # Add function vertices
#     func_name = "{} @ 0x{}".format(func.getName(), func.getEntryPoint())
#     vertex = Vertex(func)
#     digraph.add(vertex)
    
#     # Store the vertex in the graph dictionary
#     graph_dict["nodes"].append(func_name)
    
#     # Add edges for suspicious ransomware behavior calls
#     entryPoint = func.getEntryPoint()
#     instructions = listing.getInstructions(entryPoint, True)
#     for instruction in instructions:
#         addr = instruction.getAddress()
#         oper = instruction.getMnemonicString()
#         if oper == "CALL":
#             flows = instruction.getFlows()
#             if len(flows) == 1:
#                 target_addr = flows[0]
#                 target_func = fm.getFunctionAt(target_addr)
                
#                 if target_func:
#                     target_func_name = target_func.getName()
                    
#                     # Check if the function name matches ransomware-related behavior
#                     if any(behavior in target_func_name for behavior in ransomware_behaviors):
#                         dll_name = target_func_name.split(".dll")[0].upper() if target_func_name.endswith("dll") else "N/A"
#                         target_func_name = "{} @ 0x{}".format(target_func.getName(), target_func.getEntryPoint())
#                         digraph.add(Edge(vertex, Vertex(target_func)))
                        
#                         # Store the edge in the graph dictionary with DLL type and behavior hint
#                         graph_dict["edges"].append({
#                             "from": func.getName(), 
#                             "to": target_func.getName(),
#                         })

# # Print DiGraph info (optional)
# print("DiGraph info:")
# edges = digraph.edgeIterator()
# while edges.hasNext():
#     edge = edges.next()
#     from_vertex = edge.from()
#     to_vertex = edge.to()
#     print("  Edge from {} to {}".format(from_vertex, to_vertex))

# vertices = digraph.vertexIterator()
# while vertices.hasNext():
#     vertex = vertices.next()
#     print("  Vertex: {} (key: {})".format(vertex, vertex.key()))

# # Save the graph to a JSON file
# output_path = "D:\\dms_daa_el\\ransomware_graph.json"
# try:
#     json_data = json.dumps(graph_dict, indent=4)  # Convert the dictionary to a JSON string with indentation
#     writer = FileWriter(output_path)
#     writer.write(json_data)
#     writer.close()
#     print("Graph saved to {}".format(output_path))
# except Exception as e:
#     print("Failed to save graph: {}".format(e))

#Working script 1
# from ghidra.util.graph import DirectedGraph
# from ghidra.util.graph import Edge
# from ghidra.util.graph import Vertex
# from java.io import FileWriter
# import json

# # Define a list of ransomware-related API calls
# ransomware_behaviors = [
#     "InitializeCriticalSection","GetProcAddress","CreateFileA","CreateProcessA" "WriteFile", "GetFileSizeEx", "OpenProcess", 
#     "VirtualAlloc", "WriteProcessMemory", "RegCreateKeyW","RegQueryValueExA", 
#     "RegSetValue","RegCloseKey","setCurrentDirectoryW","GetCurrentDirectoryA","GetComputerNameW",
#     "GlobalFree","GlobalAlloc","DeleteCriticalSection","CryptReleaseContext","GetFileSize","ReadFile",
#     "EnterCriticalSection","LeaveCriticalSection","SetFileAttributesW","GetWindowsDirectoryW","GetTempPathW",
#     "OpenSCManagerA","OpenServiceA","CreateServiceA","StartServiceA","CloseServiceHandle","FindResourceA","LoadResource",
#     "LockResource","SizeofResource","OpenMutexA","GetModuleHandleA","VirtualProtect","CloseHandle","PulseEvent",
#     "WriteFileGather","FlushFileBuffers","VirtualLock","IsDebuggerPresent",
#     "FlushViewOfFile","EncryptFileW","GetSecurityDescriptorDacl","VirtualQuery","InterlockedExchange","DeleteObject","DispatchMessageA",
#     "ShowWindow","GetUserNameExA","GetUserDefaultLCID"
# ]

# def getAddress(offset):
#     return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

# # Initialize directed graph
# digraph = DirectedGraph()
# listing = currentProgram.getListing()
# fm = currentProgram.getFunctionManager()

# # Dictionary to store the graph
# graph_dict = {"nodes": [], "edges": []}

# funcs = fm.getFunctions(True) # True means iterate forward
# for func in funcs: 
#     # Add function vertices
#     func_name = "{} @ 0x{}".format(func.getName(), func.getEntryPoint())
#     vertex = Vertex(func)
#     digraph.add(vertex)
    
#     # Store the vertex in the graph dictionary
#     graph_dict["nodes"].append(func_name)
    
#     # Add edges for suspicious ransomware behavior calls
#     entryPoint = func.getEntryPoint()
#     instructions = listing.getInstructions(entryPoint, True)
#     for instruction in instructions:
#         addr = instruction.getAddress()
#         oper = instruction.getMnemonicString()
#         if oper == "CALL":
#             flows = instruction.getFlows()
#             if len(flows) == 1:
#                 target_addr = flows[0]
#                 target_func = fm.getFunctionAt(target_addr)
                
#                 if target_func:
#                     target_func_name = target_func.getName()
                    
#                     # Check if the function name matches ransomware-related behavior
#                     if any(behavior in target_func_name for behavior in ransomware_behaviors):
#                         dll_name = target_func_name.split(".dll")[0].upper() if target_func_name.endswith("dll") else "N/A"
#                         target_func_name = "{} @ 0x{}".format(target_func.getName(), target_func.getEntryPoint())
#                         digraph.add(Edge(vertex, Vertex(target_func)))
                        
#                         # Store the edge in the graph dictionary with DLL type and behavior hint
#                         graph_dict["edges"].append({
#                             "from": func.getName(), 
#                             "to": target_func.getName(),
#                         })

# # Print DiGraph info (optional)
# print("DiGraph info:")
# edges = digraph.edgeIterator()
# while edges.hasNext():
#     edge = edges.next()
#     from_vertex = edge.from()
#     to_vertex = edge.to()
#     print("  Edge from {} to {}".format(from_vertex, to_vertex))

# vertices = digraph.vertexIterator()
# while vertices.hasNext():
#     vertex = vertices.next()
#     print("  Vertex: {} (key: {})".format(vertex, vertex.key()))

# # Save the graph to a JSON file
# output_path = "D:\\dms_daa_el\\ransomware_graph.json"
# try:
#     json_data = json.dumps(graph_dict, indent=4)  # Convert the dictionary to a JSON string with indentation
#     writer = FileWriter(output_path)
#     writer.write(json_data)
#     writer.close()
#     print("Graph saved to {}".format(output_path))
# except Exception as e:
#     print("Failed to save graph: {}".format(e))


