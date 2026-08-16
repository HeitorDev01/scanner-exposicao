"""
translator.py

Passo 3 do projeto: traduz portas e CVEs tecnicas para linguagem
simples, que a pessoa dona do site vai realmente entender.
"""

import time
import requests


# Traducao de portas mais comuns pra linguagem simples.
# Isso e conhecimento publico, qualquer lista de "portas conhecidas"
# tem isso (a IANA mantem a lista oficial).
PORTAS_CONHECIDAS = {
    21: "FTP - transferencia de arquivos (geralmente nao deveria estar exposto)",
    22: "SSH - acesso remoto administrativo ao servidor",
    23: "Telnet - acesso remoto antigo e inseguro (se estiver aberto, e risco serio)",
    25: "SMTP - envio de e-mail",
    80: "HTTP - trafego do site sem criptografia",
    443: "HTTPS - trafego do site com criptografia (normal e esperado)",
    3306: "MySQL - banco de dados (nunca deveria estar exposto a internet)",
    3389: "RDP - acesso remoto de area de trabalho do Windows (alvo comum de ataque)",
    5432: "PostgreSQL - banco de dados (nunca deveria estar exposto a internet)",
    8080: "HTTP alternativo - geralmente um painel ou aplicacao web",
}


def explicar_porta(porta: int) -> str:
    """Devolve uma explicacao simples pra uma porta conhecida."""
    return PORTAS_CONHECIDAS.get(porta, "servico nao identificado nessa lista")


def buscar_detalhes_cve(cve_id: str) -> dict:
    """
    Busca detalhes de um CVE na NVD (National Vulnerability Database) -
    o banco de dados oficial e publico de vulnerabilidades conhecidas.
    Nao precisa de chave de API pra consultas simples como essa.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}

    response = requests.get(url, params=params, timeout=15)
    response.raise_for_status()
    data = response.json()

    vulnerabilidades = data.get("vulnerabilities", [])
    if not vulnerabilidades:
        return {}

    cve = vulnerabilidades[0]["cve"]

    # pega a descricao em ingles (a NVD normalmente so tem nesse idioma)
    descricao = ""
    for desc in cve.get("descriptions", []):
        if desc["lang"] == "en":
            descricao = desc["value"]
            break

    # pega a gravidade - nem todo CVE antigo tem essa informacao calculada
    gravidade = "desconhecida"
    metrics = cve.get("metrics", {})
    for versao_metrica in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if versao_metrica in metrics:
            gravidade = metrics[versao_metrica][0]["cvssData"].get(
                "baseSeverity", "desconhecida"
            )
            break

    return {"id": cve_id, "descricao": descricao, "gravidade": gravidade}


def traduzir_cves(lista_de_cves: list[str]) -> list[dict]:
    """
    Busca e traduz uma lista de CVEs, com uma pequena pausa entre
    cada consulta pra nao sobrecarregar a API publica da NVD (sem
    chave de API, ela limita a quantidade de consultas por minuto).
    """
    resultados = []
    for cve_id in lista_de_cves:
        try:
            detalhes = buscar_detalhes_cve(cve_id)
            if detalhes:
                resultados.append(detalhes)
        except requests.exceptions.RequestException as erro:
            print(f"  (nao consegui buscar {cve_id}: {erro})")

        time.sleep(6)

    return resultados


if __name__ == "__main__":
    print("=== Tradutor de portas ===")
    for porta in (22, 443, 3389, 3306):
        print(f"  Porta {porta}: {explicar_porta(porta)}")

    print("\n=== Tradutor de CVE ===")
    cve_teste = input(
        "Digite um CVE pra testar (ex: CVE-2021-41773) ou so aperte Enter pra pular: "
    ).strip()

    if cve_teste:
        resultado = traduzir_cves([cve_teste])
        for item in resultado:
            print(f"\n{item['id']} (gravidade: {item['gravidade']})")
            print(f"  {item['descricao']}")