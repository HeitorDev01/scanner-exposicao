"""
http_info.py

Coleta passiva sobre um dominio: IP via DNS, headers HTTP e dados do Shodan
InternetDB (portas/CVEs ja catalogadas). Nao faz scan ativo.
"""

import socket
import requests


def resolve_ip(domain: str) -> str:
    """Descobre o endereco IP de um dominio."""
    return socket.gethostbyname(domain)


def get_http_headers(domain: str) -> dict:
    """
    Faz uma requisicao HTTP normal pro dominio e devolve os headers
    de resposta - a mesma coisa que um navegador recebe.

    Tenta HTTPS primeiro e, se der qualquer tipo de falha (sem SSL,
    fora do ar, demorando demais...), tenta HTTP puro. Se as duas
    tentativas falharem, devolve um dicionario vazio em vez de
    quebrar o programa - o site so simplesmente nao respondeu.
    """
    for esquema in ("https", "http"):
        url = f"{esquema}://{domain}"
        try:
            response = requests.get(url, timeout=10)
            return dict(response.headers)
        except requests.exceptions.RequestException:
            continue  # tenta o proximo esquema (ou desiste, se ja era o ultimo)

    return {}


def get_internetdb_info(ip: str) -> dict:
    """
    Consulta o Shodan InternetDB - API publica e gratuita que devolve
    portas abertas, servicos e CVEs ja catalogados pra um IP.
    Nao precisa de chave de API pra essa consulta.
    """
    url = f"https://internetdb.shodan.io/{ip}"
    response = requests.get(url, timeout=10)

    if response.status_code == 404:
        # Shodan nao tem nada catalogado pra esse IP ainda
        return {}

    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    alvo = input("Digite o dominio (ex: example.com): ").strip()

    print(f"\nResolvendo IP de {alvo}...")
    try:
        ip = resolve_ip(alvo)
    except socket.gaierror:
        print("Nao foi possivel resolver esse dominio. Confere se digitou certo.")
    else:
        print(f"IP encontrado: {ip}\n")

        print("Buscando headers HTTP...")
        headers = get_http_headers(alvo)
        if not headers:
            print("  (nao consegui obter resposta HTTP nem HTTPS desse dominio)")
        else:
            encontrou_algum = False
            for chave in ("Server", "X-Powered-By"):
                if chave in headers:
                    print(f"  - {chave}: {headers[chave]}")
                    encontrou_algum = True
            if not encontrou_algum:
                print("  (o servidor nao expos Server nem X-Powered-By)")

        print("\nConsultando Shodan InternetDB...")
        try:
            info = get_internetdb_info(ip)
        except requests.exceptions.RequestException as erro:
            print(f"Nao consegui consultar o InternetDB: {erro}")
        else:
            if not info:
                print("Nada catalogado pra esse IP no Shodan.")
            else:
                portas = info.get("ports", [])
                cves = info.get("vulns", [])
                print(f"Portas abertas conhecidas: {portas}")
                print(f"CVEs conhecidas: {cves if cves else 'nenhuma catalogada'}")