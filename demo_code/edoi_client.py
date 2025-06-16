import httpe_client
import json
import time
import asyncio
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

# Initialize client
client = httpe_client.HttpeClient(
    port=5400,
    connect_to_edoi=True,
    edoi_ip='127.0.0.1',
    edoi_port=21199,
    edoi_target="HTTPE",
    edoi_client_name="TestC",
    silent_mode=True,
)

# Event stages in order
stages = [
    "listener_started",
    "connected_to_edoi_server",
    "path_request_sent",
    "rsa_key_request_sent",
    "rsa_key_received",
    "sending_aes_key_and_id",
    "got_token_and_cert",
    "validating_certificates",
    "handshake_complete",
]

# Track completed stages
completed_stages = set()

# Create a progress bar
progress = Progress(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}"),
    BarColumn(bar_width=20),
    TimeElapsedColumn(),
    transient=True
)
task = None

# Function to handle progress update
def make_event_handler(stage_name):
    def handler():
        completed_stages.add(stage_name)
        percent = len(completed_stages) / len(stages)
        progress.update(task, completed=len(completed_stages), description=f"[bold green]{stage_name.replace('_', ' ').capitalize()}")
    return handler

# Register all events dynamically
for stage in stages:
    client.on(stage, make_event_handler(stage))

# Main async function
async def send():
    global task
    print("Starting up client...")

    with progress:
        task = progress.add_task("[bold blue]Connecting to EDOI...", total=len(stages))
        await client.start()  # triggers progress updates
        progress.update(task, completed=len(stages), description="[bold green]Connection Complete ✅")

    print("Beginning code execution...")
    data = {"data": "12234"}

    print("SENDING POST request to /PTS")
    start_time = time.time()
    res = await client.send_request("POST", "/PTS", body=json.dumps(data))
    end_time = time.time()

    print("Time taken for POST request:", end_time - start_time, "seconds")
    print(res.status)
    print(res.json())

asyncio.run(send())
