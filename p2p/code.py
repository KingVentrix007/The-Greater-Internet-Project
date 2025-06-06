import hashlib
import random
import uuid
from typing import List, Optional, Tuple, Dict

# --- Node Definition ---

class Node:
    def __init__(self, name: str):
        self.name = name
        self.id = uuid.uuid4().hex
        self.pubkey = f"PUB_{self.id}"
        self.privkey = f"PRIV_{self.id}"
        self.neighbors: List['Node'] = []

    def __repr__(self):
        return self.name

    def compute_hashed_identity(self, salt: str) -> str:
        return hashlib.sha256((self.name + salt).encode()).hexdigest()

# --- Encryption Simulation ---

def encrypt(data: str, pubkey: str) -> str:
    return f"[{pubkey}]{data[::-1]}"

def decrypt(data: str, privkey: str) -> Optional[str]:
    expected_prefix = f"[PUB_{privkey[5:]}]"
    if data.startswith(expected_prefix):
        return data[len(expected_prefix):][::-1]
    return None

# --- Recursive Discovery Function ---

def recursive_discovery(
    current_node: Node,
    encrypted_hash: str,
    salt: str,
    visited: set,
    path: List[Node],
    target_hash: str,
    max_depth: int = 10
) -> Optional[List[Node]]:
    if current_node in visited or max_depth <= 0:
        return None
    visited.add(current_node)

    decrypted = decrypt(encrypted_hash, current_node.privkey)
    if decrypted is None:
        return None

    extracted_hash, extracted_salt = decrypted.split("::")
    current_hashed = current_node.compute_hashed_identity(extracted_salt)

    if current_hashed == target_hash:
        return path + [current_node]

    for neighbor in current_node.neighbors:
        neighbor_encrypted = encrypt(f"{extracted_hash}::{extracted_salt}", neighbor.pubkey)
        result = recursive_discovery(
            neighbor,
            neighbor_encrypted,
            extracted_salt,
            visited,
            path + [current_node],
            target_hash,
            max_depth - 1
        )
        if result:
            return result
    return None

# --- Network Setup ---

NUM_NODES = 1000
NEIGHBOR_COUNT = 10
nodes = [Node(f"Node{i}") for i in range(NUM_NODES)]

# Connect nodes randomly
for node in nodes:
    node.neighbors = random.sample([n for n in nodes if n != node], NEIGHBOR_COUNT)

# Choose client and target
target_node = random.choice(nodes)
client_node = random.choice([n for n in nodes if n != target_node])

# --- Simulate Discovery ---

# Client generates a salted target hash
salt = uuid.uuid4().hex
target_hash = target_node.compute_hashed_identity(salt)
initial_encrypted = encrypt(f"{target_hash}::{salt}", client_node.neighbors[0].pubkey)

# Begin recursive discovery
discovery_path = recursive_discovery(
    client_node.neighbors[0],
    initial_encrypted,
    salt,
    visited=set(),
    path=[client_node],
    target_hash=target_hash
)
# --- Return Path Wrapping ---

def wrap_return_path(path: List[Node], payload: str) -> str:
    """
    Onion-wrap the return payload using each node's public key in reverse order.
    """
    wrapped = payload
    for node in reversed(path):
        wrapped = encrypt(wrapped, node.pubkey)
    return wrapped

def unwrap_return_path(path: List[Node], wrapped_payload: str) -> str:
    """
    Each node unwraps one layer using its private key in forward order.
    """
    current = wrapped_payload
    for node in path:
        current = decrypt(current, node.privkey)
        if current is None:
            return "[Decryption Failed]"
    return current

# --- Simulate Return Path ---

# The destination node (Node7) prepares a response payload
response_payload = f"Hello, {discovery_path[0].name}! This is {discovery_path[-1].name}."

# Wrap the payload using the discovery path in reverse
wrapped_response = wrap_return_path(discovery_path, response_payload)

# Now simulate each node forwarding and decrypting one layer
final_message_at_client = unwrap_return_path(discovery_path, wrapped_response)

# Output results
return_result = {
    "Response Payload (original)": response_payload,
    "Wrapped Response": wrapped_response,
    "Final Message at Client": final_message_at_client,
    "Discovery Path": [n.name for n in discovery_path] if discovery_path else "Not Found"
}
print(return_result)
# --- Output Result ---

# result = {
#     "Client Node": client_node.name,
#     "Target Node": target_node.name,
#     "Salt": salt,
#     "Target Hash": target_hash,
#     "Discovery Path": [n.name for n in discovery_path] if discovery_path else "Not Found"
# }
# print(result)
