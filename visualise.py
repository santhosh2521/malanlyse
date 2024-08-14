import json
import networkx as nx
import matplotlib.pyplot as plt

# Load the graph from the JSON file
input_path = "ransomware_graph.json"
with open(input_path, 'r') as f:
    graph_data = json.load(f)

# Create a directed graph using networkx
G = nx.DiGraph()

# Add nodes and edges to the graph
# for node in graph_data["nodes"]:
#     G.add_node(node)

for edge in graph_data["edges"]:
    G.add_edge(edge["from"], edge["to"])

# Draw the graph
plt.figure(figsize=(10, 8))
pos = nx.random_layout(G)  # You can use different layouts like spring_layout, circular_layout, etc.
nx.draw(G, pos, with_labels=True, node_size=3000, node_color="skyblue", font_size=10, font_weight="bold", arrowsize=20)
plt.title("Function Call Graph")
plt.show()
