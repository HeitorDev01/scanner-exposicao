"""
port_scanner.py

Varredura ativa de portas em paralelo, com banner grabbing pra identificar
o servico/versao de cada porta aberta.

So use em alvos com autorizacao: manda trafego real pro servidor.
"""

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed


# Portas mais comuns num recon. Da pra passar outra lista via parametro.
PORTAS_TOP = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 389, 443,
    445, 465, 587, 636, 993, 995, 1080, 1433, 1521, 2049, 2082, 2083,
    2181, 2375, 2376, 3000, 3306, 3389, 4443, 4444, 5000, 5432, 5601,
    5672, 5900, 5985, 5986, 6379, 6443, 7001, 8000, 8008, 8009, 8080,
    8081, 8088, 8443, 8888, 9000, 9042, 9090, 9200, 9300, 11211, 15672,
    27017, 27018, 50070,
]

# Portas HTTP em texto puro: mandamos um GET e lemos o header Server.
PORTAS_HTTP = {80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090}

# Portas HTTP sobre TLS: precisa embrulhar o socket em SSL antes do GET.
PORTAS_HTTPS = {443, 4443, 8443, 9443}


def _ler_banner_texto(sock: socket.socket, host: str, porta: int) -> str:
    """
    Le o banner de um socket ja conectado (texto puro, sem TLS).

    Muitos servicos (SSH, FTP, SMTP...) mandam uma linha de apresentacao ao
    conectar; pras portas HTTP a gente provoca a resposta com um GET.
    """
    try:
        if porta in PORTAS_HTTP:
            pedido = f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n"
            sock.sendall(pedido.encode())
        dados = sock.recv(2048)
        return dados.decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


def _ler_banner_tls(host: str, porta: int, timeout: float) -> str:
    """
    Faz o handshake TLS e manda um GET pra ler o header Server de um
    servico HTTPS. Nao valida o certificado aqui (queremos o banner
    mesmo que o cert esteja vencido ou seja autoassinado).
    """
    contexto = ssl.create_default_context()
    contexto.check_hostname = False
    contexto.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, porta), timeout=timeout) as bruto:
            with contexto.wrap_socket(bruto, server_hostname=host) as tls:
                tls.settimeout(timeout)
                pedido = f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n"
                tls.sendall(pedido.encode())
                dados = tls.recv(2048)
                return dados.decode("utf-8", errors="replace").strip()
    except (OSError, ssl.SSLError):
        return ""


def _resumir_banner(banner: str) -> str:
    """
    Deixa o banner curto pro relatorio: pra HTTP puxa o header Server;
    pros demais servicos, a primeira linha nao vazia.
    """
    if not banner:
        return ""

    linhas = [ln.strip() for ln in banner.splitlines() if ln.strip()]
    if not linhas:
        return ""

    # Resposta HTTP: procura o header Server
    if linhas[0].startswith("HTTP/"):
        server = ""
        for linha in linhas:
            if linha.lower().startswith("server:"):
                server = linha.split(":", 1)[1].strip()
                break
        if server:
            return f"HTTP - {server}"
        return "HTTP - (sem header Server)"

    # Outro servico qualquer: primeira linha ja costuma trazer nome/versao
    primeira = linhas[0]
    return primeira[:120]


def escanear_porta(host: str, porta: int, timeout: float = 2.0) -> dict | None:
    """
    Testa UMA porta. Se estiver aberta, tenta pegar o banner.

    Returns:
        None se a porta estiver fechada/filtrada, ou um dicionario
        {"porta", "banner"} se estiver aberta.
    """
    try:
        with socket.create_connection((host, porta), timeout=timeout) as sock:
            sock.settimeout(timeout)

            if porta in PORTAS_HTTPS:
                # fecha e reabre via TLS - mais simples que fazer upgrade
                sock.close()
                banner = _ler_banner_tls(host, porta, timeout)
            else:
                banner = _ler_banner_texto(sock, host, porta)

            return {"porta": porta, "banner": _resumir_banner(banner)}
    except OSError:
        # ConnectionRefused, timeout, host sem rota etc. -> porta nao aberta
        return None


def escanear(
    host: str,
    portas: list[int] = None,
    timeout: float = 2.0,
    max_threads: int = 50,
) -> list[dict]:
    """
    Varre varias portas em paralelo e devolve so as abertas, com o banner
    de cada uma (dicts {"porta", "banner"} ordenados por porta).
    """
    if portas is None:
        portas = PORTAS_TOP

    abertas = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futuros = {
            executor.submit(escanear_porta, host, porta, timeout): porta
            for porta in portas
        }
        for futuro in as_completed(futuros):
            resultado = futuro.result()
            if resultado is not None:
                abertas.append(resultado)

    return sorted(abertas, key=lambda item: item["porta"])


if __name__ == "__main__":
    alvo = input("Digite o IP/dominio a verificar (voce precisa ter autorizacao): ").strip()
    confirmacao = (
        input("Confirma que tem autorizacao para escanear este alvo? (sim/nao): ")
        .strip()
        .lower()
    )

    if confirmacao != "sim":
        print("Verificacao cancelada.")
    else:
        print(f"\nEscaneando {len(PORTAS_TOP)} portas em {alvo} (em paralelo)...")
        resultado = escanear(alvo)
        if not resultado:
            print("Nenhuma das portas testadas respondeu como aberta.")
        else:
            print(f"\n{len(resultado)} porta(s) aberta(s):\n")
            for item in resultado:
                banner = item["banner"] if item["banner"] else "(sem banner)"
                print(f"  Porta {item['porta']:>5}: {banner}")
