from edoi_net import NetNode
from toxiproxy import Toxiproxy
import toxiproxy
import asyncio
import random

# Constants
BASE_PORT = 20000
PROXY_PORT = 21000
NUM_NODES = 200
NEIGHBOR_COUNT = 5  # adjust based on your config

async def _test_network():
    # === 1. Setup toxiproxy to simulate network latency ===
    def setup_proxies():
        toxiproxy_client =  toxiproxy.Toxiproxy()
        

        # Clean up any old proxies
        toxiproxy_client.destroy_all()
            # proxy.delete()

        print("[*] Setting up toxiproxy instances...")
        proxeys = []
        for i in range(NUM_NODES):
            real_port = BASE_PORT + i
            proxy_port = PROXY_PORT + i
            proxy_name = f"edoi_node_{i}"

            proxy = toxiproxy_client.create(
                name=proxy_name,
                listen=f"127.0.0.1:{proxy_port}",
                upstream=f"127.0.0.1:{real_port}"
            )

            # Simulate 50ms base latency with ±10ms jitter
            proxy.add_toxic(
                name="downlatency",
                type="latency",
                stream="downstream",  # delay when talking *to* the node
                attributes={"latency": 100, "jitter": 10}
            )

            proxy.add_toxic(
                name="uplatency",
                type="latency",
                stream="upstream",  # delay when talking *to* the node
                attributes={"latency": 100, "jitter": 10}
            )
            # proxy.add_toxic(
            #     name="uploss",
            #     type="loss",
            #     stream="upstream",
            #     attributes={"loss": 2.0}  # 2% packet loss
            # )

            # proxy.add_toxic(
            #     name="downloss",
            #     type="loss",
            #     stream="downstream",
            #     attributes={"loss": 2.0}
            # )


            proxy.add_toxic(
                name="downloss",
                type="bandwidth",
                stream="downstream",
                attributes={"rate": 1024}  # Simulate slow bandwidth (bytes/sec)
            )

            proxy.add_toxic(
                name="slow_downstream",
                type="bandwidth",
                stream="downstream",
                attributes={"rate": 512 * 8}  # 512 KB/s (in bits/sec)
            )

            proxy.add_toxic(
                name="slow_upstream",
                type="bandwidth",
                stream="upstream",
                attributes={"rate": 256 * 8}  # 256 KB/s
            )
        #     proxy.add_toxic(
        #     name="timeout_sim",
        #     type="timeout",
        #     stream="downstream",
        #     attributes={"timeout": 2000}  # Delay stream for 2 seconds (2000 ms)
        # )

            proxeys.append(proxy)
        for j in range(NUM_NODES):
            name = f"edoi_node_{j}"
            if(toxiproxy_client.get_proxy(name) == None):
                print(f"Failed to create proxy: {name}")
        print(f"[+] Created {NUM_NODES} proxies on ports {PROXY_PORT}–{PROXY_PORT + NUM_NODES - 1}")
        

    await asyncio.to_thread(setup_proxies)

    # === 2. Boot the nodes as usual ===
    nodes = []
    ports = list(range(BASE_PORT, BASE_PORT + NUM_NODES))
    proxy_ports = list(range(PROXY_PORT, PROXY_PORT + NUM_NODES))

    assert len(ports) == len(set(ports)), "Duplicate ports detected!"
    addresses = [("127.0.0.1", port) for port in ports]
    proxy_addresses = [("127.0.0.1", port) for port in proxy_ports]

    for i, port in enumerate(ports):
        name = f"Node{i}"
        bootstrap_candidates = [addr for j, addr in enumerate(proxy_addresses) if j != i]
        bootstrap_ips = random.sample(bootstrap_candidates, NEIGHBOR_COUNT)
        node = NetNode(name=name, port=port, bootstrap_ips=bootstrap_ips)
        nodes.append(node)

    # === 3. Populate reverse neighbor connections ===
    for i, node in enumerate(nodes):
        for ip, _ in node.neighbors.items():
            for j, other_node in enumerate(nodes):
                proxy_port = proxy_ports[j]
                if ip == ('127.0.0.1', proxy_port):
                    # Add reverse connection via proxy port
                    if ('127.0.0.1', proxy_ports[i]) not in other_node.neighbors:
                        other_node.neighbors[('127.0.0.1', proxy_ports[i])] = None

    # === 4. Start all listeners ===
    listen_tasks = [asyncio.create_task(node.listen()) for node in nodes]
    await asyncio.sleep(2)  # allow sockets to bind

    print("[+] All nodes launched and listening.")

    # === 5. Optional: Print neighbor connections ===
    neighbor_map = {}
    for node in nodes:
        neighbor_names = []
        for ip, _ in node.neighbors.items():
            for n in nodes:
                if n.port == ip[1]:
                    neighbor_names.append(n.name)
        neighbor_map[node.name] = neighbor_names

    # Start running listeners
    await asyncio.gather(*listen_tasks)

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("[*] Shutting down.")

def setup_test_network():
    asyncio.run(_test_network())

# print(__name__)
if(__name__ == "__main__"):
    setup_test_network()