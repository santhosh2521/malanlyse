import networkx as nx
import matplotlib.pyplot as plt

def find_subgraph_isomorphisms(main_graph, subgraph):
    """
    Find exact subgraph isomorphisms between the main graph and the subgraph.
    
    Parameters:
    - main_graph (nx.Graph): The main graph in which to find the subgraph isomorphisms.
    - subgraph (nx.Graph): The subgraph to find within the main graph.
    
    Returns:
    - List of dicts: Each dict represents a mapping from nodes in the subgraph to nodes in the main graph.
    """
    matcher = nx.algorithms.isomorphism.GraphMatcher(main_graph, subgraph)
    isomorphisms = [iso for iso in matcher.subgraph_isomorphisms_iter()]
    return isomorphisms

def draw_graphs(main_graph, subgraph, isomorphisms):
    """
    Draw the main graph, subgraph, and highlight the isomorphic subgraphs in the main graph.
    
    Parameters:
    - main_graph (nx.Graph): The main graph.
    - subgraph (nx.Graph): The subgraph.
    - isomorphisms (List of dicts): List of isomorphisms to highlight.
    """
    pos_main = nx.spring_layout(main_graph)
    pos_sub = nx.spring_layout(subgraph)
    
    # Draw the main graph
    plt.figure(figsize=(12, 8))
    nx.draw(main_graph, pos_main, with_labels=True, node_color='lightblue', edge_color='gray', node_size=500, font_size=10, font_weight='bold')
    
    # Draw the subgraph
    plt.figure(figsize=(8, 6))
    nx.draw(subgraph, pos_sub, with_labels=True, node_color='lightgreen', edge_color='black', node_size=500, font_size=10, font_weight='bold')
    
    # Highlight each isomorphism
    for iso in isomorphisms:
        iso_nodes = list(iso.values())
        subgraph_nodes = list(iso.keys())
        
        plt.figure(figsize=(12, 8))
        nx.draw(main_graph, pos_main, with_labels=True, node_color='lightblue', edge_color='gray', node_size=500, font_size=10, font_weight='bold')
        nx.draw_networkx_nodes(main_graph, pos_main, nodelist=iso_nodes, node_color='orange')
        nx.draw_networkx_edges(main_graph, pos_main, edgelist=nx.edges(main_graph.subgraph(iso_nodes)), edge_color='red')
        
        plt.title(f"Isomorphism Highlighted: {iso}")
        plt.show()

# Example usage
if __name__ == "__main__":
    # Create the main graph
    G = nx.Graph()
    G.add_edges_from([(1, 2), (2, 3), (3, 4), (4, 1), (1, 3)])
    
    # Create the subgraph
    H = nx.Graph()
    H.add_edges_from([(1, 2), (2, 3)])
    
    # Find subgraph isomorphisms
    isomorphisms = find_subgraph_isomorphisms(G, H)
    
    # Draw the graphs and highlight the isomorphisms
    draw_graphs(G, H, isomorphisms)
