"""
subdomain_finder.py

Descobre subdominios publicos via crt.sh (Certificate Transparency Logs).
Passivo: nao toca no alvo, so consulta um banco publico de certificados.
"""

import time
import requests


def find_subdomains(domain: str, tentativas: int = 3) -> list[str]:
    """
    Busca subdominios conhecidos de um dominio usando o crt.sh.

    Args:
        domain: o dominio que queremos investigar, ex: "example.com"
        tentativas: quantas vezes tenta de novo se o crt.sh falhar
            antes de desistir (ele e um servico gratuito e as vezes
            fica instavel, principalmente com dominios grandes)

    Returns:
        Uma lista de subdominios unicos, ordenados alfabeticamente.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    for tentativa in range(1, tentativas + 1):
        try:
            # timeout=20 evita que o programa fique travado pra sempre
            # se o crt.sh demorar pra responder
            response = requests.get(url, timeout=20)
            response.raise_for_status()  # se der erro HTTP, cai no except abaixo
            break  # deu certo, sai do loop de tentativas
        except requests.exceptions.RequestException:
            if tentativa == tentativas:
                raise  # ja tentou o maximo de vezes, agora sim desiste e avisa
            print(
                f"  crt.sh nao respondeu bem (tentativa {tentativa}/{tentativas}), "
                f"tentando de novo em 5s..."
            )
            time.sleep(5)

    data = response.json()

    subdominios = set()  # 'set' nao deixa duplicado entrar automaticamente

    for certificado in data:
        # cada certificado pode ter mais de um nome associado,
        # separados por quebra de linha dentro do campo name_value
        nomes = certificado["name_value"].split("\n")

        for nome in nomes:
            nome = nome.strip().lower()

            # descarta wildcard tipo "*.example.com" -> vira "example.com"
            if nome.startswith("*."):
                nome = nome[2:]

            if nome.endswith(domain):
                subdominios.add(nome)

    return sorted(subdominios)


if __name__ == "__main__":
    alvo = input("Digite o dominio (ex: example.com): ").strip()

    print(f"\nBuscando subdominios de {alvo} no crt.sh...\n")

    try:
        encontrados = find_subdomains(alvo)
    except requests.exceptions.RequestException as erro:
        print(f"Deu erro ao consultar o crt.sh: {erro}")
    else:
        print(f"{len(encontrados)} subdominio(s) encontrado(s):\n")
        for sub in encontrados:
            print(f"  - {sub}")