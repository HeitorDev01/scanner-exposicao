"""
tls_headers.py

Duas checagens leves (uma conexao, igual a de um navegador):

1. Headers de seguranca (HSTS, CSP, X-Frame-Options...): aponta os que
   faltam e o risco de cada ausencia.
2. Configuracao TLS: versao aceita, cifra e dados do certificado (emissor,
   expiracao), sinalizando TLS antigo ou certificado vencido.
"""

import socket
import ssl
from datetime import datetime, timezone


# Cada header de seguranca e o risco de nao te-lo - o relatorio usa o texto.
HEADERS_SEGURANCA = {
    "Strict-Transport-Security": (
        "Forca o navegador a sempre usar HTTPS. Sem ele, da pra rebaixar "
        "a conexao pra HTTP e interceptar o trafego."
    ),
    "Content-Security-Policy": (
        "Controla de onde a pagina pode carregar scripts/recursos. Sem ele, "
        "fica muito mais facil explorar falhas de XSS (injecao de codigo)."
    ),
    "X-Frame-Options": (
        "Impede que o site seja embutido em iframe de terceiros. Sem ele, "
        "abre espaco pra clickjacking (enganar o usuario a clicar em algo)."
    ),
    "X-Content-Type-Options": (
        "Impede o navegador de 'adivinhar' o tipo do arquivo. Sem ele, um "
        "upload malicioso pode ser interpretado como script."
    ),
    "Referrer-Policy": (
        "Controla quanta informacao de origem vaza ao clicar em links "
        "externos. Sem ele, URLs internas podem vazar pra outros sites."
    ),
    "Permissions-Policy": (
        "Restringe acesso a camera, microfone, localizacao etc. Sem ele, "
        "scripts de terceiros podem pedir permissoes que nao deveriam."
    ),
}


def analisar_headers(headers: dict) -> dict:
    """
    Compara os headers recebidos com a lista de headers de seguranca
    esperados.

    Args:
        headers: dicionario de headers HTTP (o mesmo que get_http_headers
            devolve). A comparacao ignora maiusculas/minusculas.

    Returns:
        {"presentes": [...], "ausentes": [{"header", "risco"}, ...]}
    """
    # normaliza as chaves recebidas pra comparar sem se importar com caixa
    recebidos = {chave.lower() for chave in headers.keys()}

    presentes = []
    ausentes = []
    for header, risco in HEADERS_SEGURANCA.items():
        if header.lower() in recebidos:
            presentes.append(header)
        else:
            ausentes.append({"header": header, "risco": risco})

    return {"presentes": presentes, "ausentes": ausentes}


def analisar_tls(dominio: str, porta: int = 443, timeout: float = 8.0) -> dict:
    """
    Faz o handshake TLS e coleta a versao do protocolo, a cifra e os
    dados do certificado.

    Returns:
        Um dict com o que foi possivel coletar. Se nem conectar der,
        devolve {"disponivel": False, "erro": "..."}.
    """
    contexto = ssl.create_default_context()

    try:
        with socket.create_connection((dominio, porta), timeout=timeout) as bruto:
            with contexto.wrap_socket(bruto, server_hostname=dominio) as tls:
                versao = tls.version()  # ex "TLSv1.3"
                cifra = tls.cipher()    # (nome, protocolo, bits)
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as erro:
        # conectou mas o certificado nao valida (vencido, nome errado,
        # autoassinado...). Isso ja e um achado, entao registramos.
        return {
            "disponivel": True,
            "cert_valido": False,
            "erro": f"certificado nao confiavel: {erro.verify_message}",
            "versao": "",
            "cifra": "",
            "emissor": "",
            "expira_em": "",
            "dias_para_expirar": None,
            "avisos": ["O certificado nao passou na validacao padrao."],
        }
    except (OSError, ssl.SSLError) as erro:
        return {"disponivel": False, "erro": str(erro)}

    resultado = {
        "disponivel": True,
        "cert_valido": True,
        "erro": "",
        "versao": versao,
        "cifra": cifra[0] if cifra else "",
        "emissor": "",
        "expira_em": "",
        "dias_para_expirar": None,
        "avisos": [],
    }

    # Quem emitiu o certificado
    emissor = dict(x[0] for x in cert.get("issuer", []))
    resultado["emissor"] = emissor.get("organizationName", emissor.get("commonName", ""))

    # Data de expiracao -> quantos dias faltam
    validade = cert.get("notAfter")
    if validade:
        try:
            expira = datetime.strptime(validade, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            resultado["expira_em"] = expira.strftime("%d/%m/%Y")
            dias = (expira - datetime.now(timezone.utc)).days
            resultado["dias_para_expirar"] = dias
            if dias < 0:
                resultado["avisos"].append("O certificado JA ESTA VENCIDO.")
            elif dias < 30:
                resultado["avisos"].append(
                    f"O certificado vence em {dias} dias - renove logo."
                )
        except ValueError:
            pass

    # Versao de TLS antiga e um risco conhecido
    if versao in ("TLSv1", "TLSv1.1", "SSLv3"):
        resultado["avisos"].append(
            f"O servidor aceitou {versao}, uma versao antiga e insegura. "
            f"O ideal e aceitar apenas TLS 1.2 ou superior."
        )

    return resultado


if __name__ == "__main__":
    # Pequena demo do modulo de headers com um exemplo ficticio
    print("=== Analise de headers (exemplo) ===")
    exemplo = {"Server": "nginx", "X-Content-Type-Options": "nosniff"}
    relatorio = analisar_headers(exemplo)
    print(f"Presentes: {relatorio['presentes']}")
    print("Ausentes:")
    for item in relatorio["ausentes"]:
        print(f"  - {item['header']}")

    print("\n=== Analise de TLS ===")
    alvo = input("Digite um dominio pra checar o TLS (ex: exemplo.com): ").strip()
    if alvo:
        tls = analisar_tls(alvo)
        if not tls["disponivel"]:
            print(f"Nao consegui fazer o handshake TLS: {tls['erro']}")
        else:
            print(f"Versao TLS: {tls['versao'] or '(nao identificada)'}")
            print(f"Cifra: {tls['cifra'] or '(nao identificada)'}")
            print(f"Emissor: {tls['emissor'] or '(nao identificado)'}")
            print(f"Expira em: {tls['expira_em'] or '(nao identificado)'}")
            for aviso in tls["avisos"]:
                print(f"  ! {aviso}")
