import httpe_client
import json
import time
import asyncio
import random
import winsound
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.prompt import Prompt
from rich.spinner import Spinner
from rich.table import Table



# === Config ===
THEME = "dialup"

# === Shared Variables ===
console = Console()
completed_stages = []
error_occurred = {"status": False, "message": None}

# === Connection Stages ===
stages = [
    "listener_started",
    "connected_to_edoi_server",
    "path_request_sent",
    "waiting_for_edoi_path",
    "edoi_path_received",
    "sending_rsa_key_request",
    "rsa_key_received",
    "sending_aes_key_and_id",
    "got_token_and_cert",
    "validating_certificates",
    "handshake_complete",
]

# === Event Handlers ===
def make_event_handler(stage_name):
    def handler():
        pretty = stage_name.replace("_", " ").capitalize()
        completed_stages.append(pretty)
    return handler

def handle_general_error(message):
    error_occurred["status"] = True
    error_occurred["message"] = str(message)
def handle_no_path():
    error_occurred["status"] = True
    error_occurred["message"] = (
        "No path to the server could be established.\n"
        "This usually means the network is saturated or the target is unreachable.\n"
        "You can try again later, or use a different server name."
    )

def handle_packet_timeout():
    error_occurred["status"] = True
    error_occurred["message"] = ("The message timed out")
# === Beep Patterns ===
beep_patterns = [
    [(400, 200), (600, 150)],
    [(800, 100), (1000, 200), (1200, 100)],
    [(300, 200), (1400, 150), (1200, 100)],
    [(900, 300), (1100, 150)],
    [(1000, 200), (1000, 200)],
    [(1500, 100), (1600, 200)]
]

def play_beep_pattern(index):
    pattern = beep_patterns[index % len(beep_patterns)]
    for freq, dur in pattern:
        winsound.Beep(freq, dur)

# === UI Dial-Up Animation ===
async def dialup_runner():
    with Live(console=console, refresh_per_second=4) as live:
        last_len = 0
        while not error_occurred["status"] and len(completed_stages) < len(stages):
            current = completed_stages[-1] if completed_stages else "Connecting modem..."
            # noise_str = random.choice(["*bzzt*", "*krrr*", "*ping*", "*bip*", "*zzzzz*", "*pop*"])
            # dots = "." * (len(completed_stages) % 5)

            text = Text()
            text.append(f"{current}", style="bold magenta")
            table = Table.grid(padding=1)
            table.add_row(Spinner("dots"), text)
            live.update(Panel(table, title="📞 Dial-up in progress...", border_style="bright_blue"))
            # live.update(Panel(Spinner("dots", text="Go"), title="Working"))
            if len(completed_stages) > last_len:
                await asyncio.to_thread(play_beep_pattern, len(completed_stages))
                last_len = len(completed_stages)
            
            await asyncio.sleep(0.5)

        if error_occurred["status"]:
            err_text = Text("❌ Connection failed\n", justify="center", style="red bold")
            err_text.append(f"{error_occurred['message']}", style="dim")
            live.update(Panel(err_text, title="🚨 Error", border_style="red"))
            
        else:
            success_text = Text("✅ Connected to the internet!\n", justify="center", style="green bold")
            success_text.append("Welcome back, User.", style="dim")
            live.update(Panel(success_text, title="🎉 Connection Established", border_style="green"))

# === Main Application Logic ===
async def send():
    console.print("[bold cyan]📡 HTTPE Client Booting...[/]")

    edoi_target = Prompt.ask("[yellow]Enter Server Name (EDOI Target)[/]")
    client_name = Prompt.ask("[yellow]Enter Your Client Name[/]")

    client = httpe_client.HttpeClient(
        port=5400,
        connect_to_edoi=True,
        edoi_ip='127.0.0.1',
        edoi_port=21199,
        edoi_target=edoi_target,
        edoi_client_name=client_name,
        silent_mode=True
    )

    for stage in stages:
        client.on(stage, make_event_handler(stage))

    client.on("general_error", handle_general_error)
    client.on("no_path_response_received", handle_no_path)
    client.on("response_timeout",handle_packet_timeout)
    ui_task = asyncio.create_task(dialup_runner())
    await client.start()
    await asyncio.sleep(0.5)

    if error_occurred["status"]:
        console.print(f"[bold red]✖ HTTPE Handshake Failed: {error_occurred['message']}")
        return

    console.print("[bold green]✓ Connection Established. Welcome![/]")

    while True:
        action = Prompt.ask("[cyan]Type 'send' to send a message or 'recv' to receive", choices=["send", "recv"], default="recv")

        if error_occurred["status"]:
            console.print(f"[bold red]✖ Error: {error_occurred['message']}")
            break

        if action == "recv":
            password = Prompt.ask("[bold]Enter Password", password=True)
            body = {"password": password}

            console.print("[green]📨 Requesting message from server...[/]")
            start_time = time.time()
            res = await client.send_request("POST", "/get_message", body=json.dumps(body))
            end_time = time.time()

        elif action == "send":
            msg = Prompt.ask("[bold green]Enter Message to Send")
            password = Prompt.ask("[bold]Enter Password (optional)", default="")
            body = {"message": msg, "password": password}
            console.print("[magenta]📡 Sending message to server...[/]")
            start_time = time.time()
            res = await client.send_request("POST", "/send_message", body=json.dumps(body))
            end_time = time.time()

        # Check again after request in case an error occurred
        if error_occurred["status"]:
            console.print(f"[bold red]✖ Error occurred during request: {error_occurred['message']}")
            break

        console.print(f"[yellow]Response Time:[/] {end_time - start_time:.2f} sec")
        console.print(f"[blue]Status:[/] {res.status}")
        console.print(f"[white]Body:[/] {res.body()}")

        again = Prompt.ask("[bold cyan]Do you want to send or receive another message? (y/n)", choices=["y", "n"])
        if again == "n":
            console.print("[dim]Closing HTTPE client. Goodbye!")
            break

# === Entrypoint ===
if __name__ == "__main__":
    asyncio.run(send())
