import json
import networkx as nx
import matplotlib.pyplot as plt


input_path = "ransomware_graph.json"
with open(input_path, 'r') as f:
    graph_data = json.load(f)


G = nx.DiGraph()


# for node in graph_data["nodes"]:
#     G.add_node(node)

for edge in graph_data["edges"]:
    G.add_edge(edge["from"], edge["to"])


plt.figure(figsize=(10, 8))
pos = nx.random_layout(G)  
nx.draw(G, pos, with_labels=True, node_size=3000, node_color="skyblue", font_size=10, font_weight="bold", arrowsize=20)
plt.title("Function Call Graph")
plt.show()
