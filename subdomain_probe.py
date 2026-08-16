"""
subdomain_probe.py

Sondagem ativa dos subdominios listados pelo subdomain_finder (crt.sh):
resolve DNS e bate HTTP em cada um pra descobrir quais estao vivos, qual IP
tem e o que expoem (status, servidor, titulo). E onde a superficie de
ataque real aparece - o subdominio esquecido (staging, dev, admin) costuma
ser o elo fraco.

So use com autorizacao: resolve DNS e faz requisicoes pra cada subdominio.
"""

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


CABECALHO = {
    "User-Agent": "scanner-exposicao/2.0 (recon autorizado)"
}

# Extrai o <title> da pagina, so pra dar contexto no relatorio.
_RE_TITULO = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extrair_titulo(html: str) -> str:
    """Puxa o texto do <title> da pagina, se houver."""
    achado = _RE_TITULO.search(html)
    if not achado:
        return ""
    titulo = re.sub(r"\s+", " ", achado.group(1)).strip()
    return titulo[:80]


def sondar_subdominio(subdominio: str, timeout: float = 6.0) -> dict | None:
    """
    Resolve e tenta acessar um subdominio.

    Returns:
        None se o subdominio nem resolve em DNS (esta morto), ou um dict
        com o que descobrimos. Se resolve mas nao responde HTTP, ainda
        devolve o registro (o IP sozinho ja e informacao).
    """
    try:
        ip = socket.gethostbyname(subdominio)
    except socket.gaierror:
        return None  # nao resolve -> considera morto

    registro = {
        "subdominio": subdominio,
        "ip": ip,
        "status": None,
        "servidor": "",
        "titulo": "",
        "esquema": "",
    }

    for esquema in ("https", "http"):
        url = f"{esquema}://{subdominio}"
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                headers=CABECALHO,
                verify=False,
                allow_redirects=True,
            )
        except requests.exceptions.RequestException:
            continue

        registro["status"] = resp.status_code
        registro["servidor"] = resp.headers.get("Server", "")
        registro["esquema"] = esquema
        # so tenta titulo se a resposta parecer HTML
        tipo = resp.headers.get("Content-Type", "")
        if "html" in tipo.lower():
            registro["titulo"] = _extrair_titulo(resp.text)
        break  # deu certo num esquema, nao precisa tentar o outro

    return registro


def sondar_lista(
    subdominios: list[str],
    timeout: float = 6.0,
    max_threads: int = 30,
) -> list[dict]:
    """
    Sonda uma lista de subdominios em paralelo e devolve so os que
    resolveram (estao vivos), ordenados pelo nome.

    Args:
        subdominios: lista de nomes (tipicamente vinda do subdomain_finder)
        timeout: tempo maximo por subdominio
        max_threads: quantos sondar ao mesmo tempo

    Returns:
        Lista de dicts dos subdominios vivos.
    """
    vivos = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futuros = [
            executor.submit(sondar_subdominio, sub, timeout)
            for sub in subdominios
        ]
        for futuro in as_completed(futuros):
            resultado = futuro.result()
            if resultado is not None:
                vivos.append(resultado)

    return sorted(vivos, key=lambda item: item["subdominio"])


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()

    # Da pra rodar sozinho: ele busca os subdominios no crt.sh e ja sonda.
    from subdomain_finder import find_subdomains

    alvo = input("Digite o dominio (ex: exemplo.com): ").strip()
    confirmacao = (
        input("Confirma que tem autorizacao para sondar os subdominios? (sim/nao): ")
        .strip()
        .lower()
    )

    if confirmacao != "sim":
        print("Verificacao cancelada.")
    else:
        print(f"\nBuscando subdominios de {alvo} no crt.sh...")
        try:
            lista = find_subdomains(alvo)
        except requests.exceptions.RequestException as erro:
            print(f"Nao consegui buscar os subdominios: {erro}")
            lista = []

        if lista:
            print(f"{len(lista)} subdominio(s) listado(s). Sondando quais estao vivos...\n")
            vivos = sondar_lista(lista)
            print(f"{len(vivos)} subdominio(s) vivo(s):\n")
            for item in vivos:
                partes = [f"{item['subdominio']} -> {item['ip']}"]
                if item["status"] is not None:
                    partes.append(f"HTTP {item['status']}")
                if item["servidor"]:
                    partes.append(item["servidor"])
                if item["titulo"]:
                    partes.append(f'"{item["titulo"]}"')
                print("  " + "  |  ".join(partes))
