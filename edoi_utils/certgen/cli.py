import httpe_core.httpe_cert as httpe_cert
import httpe_core.httpe_keys as httpe_keys
import argparse
import os
import shutil
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import track

console = Console()

def parse_args():
    parser = argparse.ArgumentParser(description="Certificate and key generation utility for HTTPE/EDOI")
    parser.add_argument("--host", type=str, default="localhost", help="Hostname to bind to certificate (default: localhost)")
    parser.add_argument("--client-dir", type=str, default=os.getcwd(), help="Where to move client public key (default: current dir)")
    parser.add_argument("--server-dir", type=str, default=os.getcwd(), help="Where to move server private key and cert (default: current dir)")
    parser.add_argument("--cert-dir", type=str, default=os.getcwd(), help="Where to move the .ctre certificate file (default: current dir)")
    parser.add_argument("--cert-days", type=int, default=100, help="How long the certificate should be valid for (default: 100 days)")
    return parser.parse_args()

def move_file(src, dest_dir, name=None):
    if not os.path.exists(src):
        console.print(f"[bold red] Missing:[/bold red] {src}")
        return False
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, name or os.path.basename(src))
    shutil.move(src, dest)
    console.print(f"[green]✔[/green] Moved [bold]{os.path.basename(src)}[/bold] → [cyan]{dest_dir}[/cyan]")
    return True

def main():
    args = parse_args()
    console.rule("[bold blue] HTTPE/EDOI Certificate & Key Generator")

    with console.status("Generating PEM files..."):
        httpe_cert.create_pem_files(args.client_dir, args.server_dir)

    with console.status("Generating RSA keypair..."):
        pub_key, _ = httpe_keys.save_keys_rsa_keys()

    with console.status("Creating certificate..."):
        httpe_cert.create_corticate(
            hostname=args.host,
            save=True,
            cert_pub_key=pub_key,
            valid_time_days=args.cert_days
        )

    # Move files to their proper locations
    console.rule("[bold yellow] Organizing Files")
    move_file("public.pem", args.client_dir)
    move_file("private_key.pem", args.server_dir)
    move_file("public_key.edoi", args.server_dir)
    move_file("private_key.edoi", args.server_dir)
    move_file("cert.crte", args.cert_dir)

    console.rule("[bold green] Done")
    console.print(Panel.fit(
        Text.from_markup(
            "All files generated and moved successfully.\n\n"
            "📌 Please note:\n"
            f"- cert.ctre is bound to [bold] {args.host} [/bold] and valid for [bold]{args.cert_days} days[/bold].\n"
            "While changing where the server/client look for files is supported, it is not recommended at the moment..\n"
            "- If a file isn't found, this utility will alert you.",
            justify="left"
        ),
        title="Certificate Generation Complete",
        border_style="bright_blue"
    ))

if __name__ == "__main__":
    main()
