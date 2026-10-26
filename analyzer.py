import socket
import sys
import dns.resolver
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

console = Console()

BANNER = r"""
[bold cyan]
  ____                        _            _                     
 |  _ \  ___  _ __ ___   __ _(_)_ __      / \   _ __   __ _  ___ 
 | | | |/ _ \| '_ ` _ \ / _` | | '_ \    / _ \ | '_ \ / _` |/ __|
 | |_| | (_) | | | | | | (_| | | | | |  / ___ \| | | | (_| | (__ 
 |____/ \___/|_| |_| |_|\__,_|_|_| |_| /_/   \_\_| |_|\__,_|\___|                                    
[/bold cyan]
[bold yellow]  [*] Herramienta OSINT de Reconocimiento y Seguridad v1.0[/bold yellow]
"""

def get_ip_info(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        if res.status_code == 200:
            return res.json()
    except:
        pass
    return {}

def check_headers(domain):
    url = f"https://{domain}"
    headers_to_check = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options"
    ]
    results = {}
    try:
        r = requests.get(url, timeout=4, allow_redirects=True)
        for h in headers_to_check:
            if h in r.headers:
                results[h] = "[green]✔ Presente[/green]"
            else:
                results[h] = "[red]✖ No configurado[/red]"
    except:
        results["Error"] = "[red]No se pudo conectar vía HTTPS[/red]"
    return results

def run_scan(domain_target):
    domain = domain_target.replace("https://", "").replace("http://", "").split("/")[0]

    with console.status(f"[bold cyan]Analizando objetivo: {domain}...[/bold cyan]", spinner="dots"):
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            console.print(f"[bold red][!] Error: No se pudo resolver la IP para {domain}.[/bold red]")
            return

        geo = get_ip_info(ip)
        country = geo.get("country", "Desconocido")
        city = geo.get("city", "Desconocido")
        isp = geo.get("isp", "Desconocido")

        dns_records = {}
        for rtype in ['A', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                dns_records[rtype] = [str(r) for r in answers]
            except:
                dns_records[rtype] = ["No encontrados"]

        headers_status = check_headers(domain)

    console.print(Panel(f"[bold white]Objetivo:[/bold white] [cyan]{domain}[/cyan]\n[bold white]Dirección IP:[/bold white] [green]{ip}[/green]", title="[bold yellow]Resultado del Escaneo[/bold yellow]", expand=False))

    geo_table = Table(title="Geolocalización e ISP")
    geo_table.add_column("Parámetro", style="cyan")
    geo_table.add_column("Detalle", style="white")
    geo_table.add_row("País", country)
    geo_table.add_row("Ciudad", city)
    geo_table.add_row("ISP / Proveedor", isp)
    console.print(geo_table)

    dns_table = Table(title="Registros DNS")
    dns_table.add_column("Tipo", style="cyan")
    dns_table.add_column("Valores", style="white")
    for rtype, vals in dns_records.items():
        dns_table.add_row(rtype, "\n".join(vals))
    console.print(dns_table)

    sec_table = Table(title="Cabeceras de Seguridad HTTP")
    sec_table.add_column("Cabecera", style="cyan")
    sec_table.add_column("Estado", style="white")
    for h, status in headers_status.items():
        sec_table.add_row(h, status)
    console.print(sec_table)

    console.print("\n[bold green][✔] Escaneo finalizado con éxito.[/bold green]\n")

def main():
    console.clear()
    rprint(BANNER)
    
    if len(sys.argv) >= 2:
        run_scan(sys.argv[1])
        return

    while True:
        domain_target = console.input("[bold green]>[/bold green] Ingresa el dominio a escanear (ej: github.com): ").strip()

        if not domain_target:
            console.print("[bold red][!] Debes ingresar un dominio válido.[/bold red]")
            continue

        if domain_target.lower() in ["salir", "exit", "q"]:
            console.print("[bold cyan]Saliendo de la herramienta.[/bold cyan]")
            break

        run_scan(domain_target)

        continuar = console.input("[bold yellow]¿Quieres escanear otro dominio? (y/n): [/bold yellow]").strip().lower()
        if continuar not in ["s", "si", "y", "yes"]:
            console.print("[bold cyan]Saliendo de la herramienta.[/bold cyan]")
            break
        console.clear()
        rprint(BANNER)

if __name__ == "__main__":
    main()