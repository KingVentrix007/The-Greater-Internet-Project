import hashlib
from edoi import Node, recursive_discovery, wrap_return_path, unwrap_return_path
import uuid
import random
# --- Build Network ---
NUM_NODES = 100
NEIGHBOR_COUNT = 10
nodes = [Node(f"Node{i}") for i in range(NUM_NODES)]
for node in nodes:
    node.neighbors = random.sample([n for n in nodes if n != node], NEIGHBOR_COUNT)

# --- Choose Client and Target ---
target_node = random.choice(nodes)

client_node = random.choice([n for n in nodes if n != target_node])

# --- Prepare Discovery ---
salt = uuid.uuid4().hex
target_hash = target_node.compute_hashed_identity(salt)
initial_data = f"{target_hash}::{salt}".encode()
start_neighbor = random.choice(client_node.neighbors)
initial_encrypted = start_neighbor.encrypt(initial_data)

# --- Run Discovery ---
discovery_path = recursive_discovery(
    start_neighbor, initial_encrypted, salt, set(), [client_node], target_hash
)

if discovery_path:
    response = f"Hello {discovery_path[0].name}, this is {discovery_path[-1].name}"
    wrapped = wrap_return_path(discovery_path, response)
    final_message = unwrap_return_path(discovery_path, wrapped)

    print("DISCOVERY PATH:", " → ".join(n.name for n in discovery_path))
    print("FINAL MESSAGE:", final_message)
else:
    print("Target not found")


import plotly.graph_objects as go
import networkx as nx

# Build graph
G = nx.Graph()

for node in nodes:
    G.add_node(node.name, label=node.name)

for node in nodes:
    for neighbor in node.neighbors:
        G.add_edge(node.name, neighbor.name, color='gray', layer='neighbors')

# Add discovery path as special layer
if discovery_path:
    path_edges = [(discovery_path[i].name, discovery_path[i + 1].name) for i in range(len(discovery_path) - 1)]
    for u, v in path_edges:
        G.add_edge(u, v, color='red', layer='path')

# Layout
pos = nx.spring_layout(G, seed=42)
for node in G.nodes():
    G.nodes[node]['pos'] = pos[node]

# Separate edges by layer
edge_traces = {'neighbors': [], 'path': []}
for u, v, data in G.edges(data=True):
    x0, y0 = G.nodes[u]['pos']
    x1, y1 = G.nodes[v]['pos']
    edge_trace = go.Scatter(
        x=[x0, x1], y=[y0, y1],
        line=dict(width=1.5, color=data['color']),
        hoverinfo='none',
        mode='lines',
        visible=True if data['layer'] == 'path' else 'legendonly',
        name='Discovery Path' if data['layer'] == 'path' else 'Neighbor Links'
    )
    edge_traces[data['layer']].append(edge_trace)

# Node trace
node_trace = go.Scatter(
    x=[pos[node][0] for node in G.nodes()],
    y=[pos[node][1] for node in G.nodes()],
    text=[node for node in G.nodes()],
    mode='markers+text',
    textposition='top center',
    hoverinfo='text',
    marker=dict(
        showscale=False,
        color=[
            'green' if node == target_node.name else
            'orange' if node == client_node.name else
            'skyblue'
            for node in G.nodes()
        ],
        size=10,
        line_width=2
    ),
    name='Nodes'
)

# Create figure
fig = go.Figure(
    data=edge_traces['neighbors'] + edge_traces['path'] + [node_trace],
    layout=go.Layout(
        title='Interactive EDOI Discovery Visualization',
        titlefont_size=16,
        showlegend=True,
        hovermode='closest',
        margin=dict(b=20, l=5, r=5, t=40),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        legend=dict(x=0.85, y=1)
    )
)

fig.show()
