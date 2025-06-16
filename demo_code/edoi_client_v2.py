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

# === Config ===
THEME = "dialup"  # Change to "military" or "starwars"

# === Shared Variables ===
console = Console()
completed_stages = []

# === Connection Stages (do not change) ===
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

# === Register Event Handlers ===
def make_event_handler(stage_name):
    def handler():
        pretty = stage_name.replace("_", " ").capitalize()
        completed_stages.append(pretty)
    return handler

# === Client Setup ===
client = httpe_client.HttpeClient(
    port=5400,
    connect_to_edoi=True,
    edoi_ip='127.0.0.1',
    edoi_port=21199,
    edoi_target="HTTPE",
    edoi_client_name="TestC",
    silent_mode=True
)

for stage in stages:
    client.on(stage, make_event_handler(stage))

# === Sound Pattern ===
beep_patterns = [
    [(400, 200), (600, 150)],                  # Modem init
    [(800, 100), (1000, 200), (1200, 100)],    # Dialing
    [(300, 200), (1400, 150), (1200, 100)],    # Handshake
    [(900, 300), (1100, 150)],                 # Negotiation
    [(1000, 200), (1000, 200)],                # Auth
    [(1500, 100), (1600, 200)]                 # Final
]

def play_beep_pattern(index):
    pattern = beep_patterns[index % len(beep_patterns)]
    for freq, dur in pattern:
        winsound.Beep(freq, dur)

# === Dial-up Runner ===
async def dialup_runner():
    with Live(console=console, refresh_per_second=4) as live:
        last_len = 0
        while len(completed_stages) < len(stages):
            current = completed_stages[-1] if completed_stages else "Connecting modem..."
            noise_str = random.choice(["*bzzt*", "*krrr*", "*ping*", "*bip*", "*zzzzz*", "*pop*"])
            dots = "." * (len(completed_stages) % 5)

            text = Text()
            text.append(f"{current}\n", style="bold magenta")
            text.append(f"{noise_str}{dots}",style="dim sy")

            live.update(Panel(text, title="📞 Dial-up in progress...", border_style="bright_blue"))

            # Only play sound when new stage appears
            if len(completed_stages) > last_len:
                await asyncio.to_thread(play_beep_pattern, len(completed_stages))
                last_len = len(completed_stages)

            await asyncio.sleep(0.5)

        success_text = Text("[green bold]✅ Connected to the internet!\n[dim]Welcome back, Commander.", justify="center")
        live.update(Panel(success_text, title="🎉 Connection Established", border_style="green"))

# === Other Themes ===
async def military_runner():
    last_shown = 0
    while len(completed_stages) < len(stages):
        for i in range(last_shown, len(completed_stages)):
            console.print(f"[bold green]>> {completed_stages[i]}")
        last_shown = len(completed_stages)
        await asyncio.sleep(0.5)
    console.print("[bold cyan]>> Handshake complete. Terminal online.")

async def starwars_runner():
    with Live(console=console, refresh_per_second=5) as live:
        while len(completed_stages) < len(stages):
            current = completed_stages[-1] if completed_stages else "Holo-link initializing..."
            glitches = ''.join(random.choice(['.', '*', '~', ' ']) for _ in range(random.randint(5, 10)))
            txt = f"[bold cyan]{current}\n[dim]{glitches}"
            panel = Panel(txt, title="[blue]Comm-Link", border_style="magenta")
            live.update(panel)
            await asyncio.sleep(0.5)
        console.print("[green bold]★ Secure Transmission Established ★")

# === Main Send Function ===
async def send():
    console.print("[bold]Booting HTTPE Client...[/]")

    # Launch themed loader
    if THEME == "dialup":
        ui_task = asyncio.create_task(dialup_runner())
    elif THEME == "military":
        ui_task = asyncio.create_task(military_runner())
    elif THEME == "starwars":
        ui_task = asyncio.create_task(starwars_runner())
    else:
        raise ValueError("Unknown theme selected.")

    await client.start()  # Triggers event callbacks
    await asyncio.sleep(0.5)  # Small buffer

    # Cancel the UI animation
    ui_task.cancel()

    console.print("[bold green]✓ HTTPE Handshake Completed")

    # Send a sample POST request
    data = {"data": "12234"}
    console.print("SENDING POST to /PTS...")

    start_time = time.time()
    res = await client.send_request("POST", "/PTS", body=json.dumps(data))
    end_time = time.time()

    console.print(f"[yellow]Response Time:[/] {end_time - start_time:.2f} sec")
    console.print(f"[blue]Status:[/] {res.status}")
    console.print(f"[white]Body:[/] {res.json()}")

# === Entrypoint ===
if __name__ == "__main__":
    asyncio.run(send())
