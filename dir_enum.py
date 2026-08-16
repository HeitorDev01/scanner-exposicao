"""
dir_enum.py

Enumeracao de caminhos e arquivos sensiveis expostos (.git/, .env, paineis
de admin, backups...). Reporta o status de cada um: 200 = abriu publico,
401/403 = existe mas protegido.

So use com autorizacao: manda varias requisicoes pro alvo.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


# Caminhos que, se acessiveis, quase sempre indicam um vazamento.
CAMINHOS_SENSIVEIS = [
    # Repositorio de codigo exposto (da pra baixar o fonte inteiro)
    ".git/HEAD",
    ".git/config",
    ".svn/entries",
    ".hg/requires",
    # Segredos / configuracao
    ".env",
    ".env.local",
    ".env.production",
    "config.php",
    "wp-config.php.bak",
    "web.config",
    "application.yml",
    "docker-compose.yml",
    ".aws/credentials",
    ".npmrc",
    # Backups e dumps largados
    "backup.zip",
    "backup.sql",
    "backup.tar.gz",
    "dump.sql",
    "database.sql",
    "db.sql",
    "site.zip",
    "www.zip",
    # Arquivos de metadados / listagem
    ".DS_Store",
    ".htaccess",
    ".htpasswd",
    "robots.txt",
    "sitemap.xml",
    "phpinfo.php",
    "info.php",
    # Paineis e areas administrativas
    "admin/",
    "administrator/",
    "wp-admin/",
    "wp-login.php",
    "login",
    "phpmyadmin/",
    "adminer.php",
    "server-status",
    "server-info",
    "actuator/health",
    "api/",
    "swagger-ui.html",
    "swagger/index.html",
    ".well-known/security.txt",
]

# Status que valem a pena reportar. 200 = achou mesmo. 401/403 = existe
# mas ta protegido (ainda revela que o recurso ta la). 301/302 pode ser
# um redirect pra tela de login, tambem interessante.
STATUS_INTERESSANTES = {200, 401, 403, 301, 302}

CABECALHO = {
    "User-Agent": "scanner-exposicao/2.0 (recon autorizado)"
}


def _significado_status(status: int) -> str:
    """Traduz o codigo HTTP pro que ele indica neste contexto."""
    return {
        200: "acessivel publicamente (200)",
        401: "existe, exige autenticacao (401)",
        403: "existe, acesso proibido (403)",
        301: "redireciona (301)",
        302: "redireciona (302)",
    }.get(status, f"status {status}")


def _testar_caminho(base_url: str, caminho: str, timeout: float) -> dict | None:
    """
    Pede um caminho e devolve um registro se o status for interessante.

    Usa allow_redirects=False de proposito: queremos ver o 301/302 em si
    (um redirect pra /login ja e um sinal), nao seguir cegamente.
    """
    url = f"{base_url}/{caminho}"
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers=CABECALHO,
            verify=False,  # nao queremos falhar por certificado invalido
        )
    except requests.exceptions.RequestException:
        return None

    if resp.status_code in STATUS_INTERESSANTES:
        return {
            "caminho": caminho,
            "url": url,
            "status": resp.status_code,
            "significado": _significado_status(resp.status_code),
            "tamanho": len(resp.content),
        }
    return None


def enumerar(
    base_url: str,
    caminhos: list[str] = None,
    timeout: float = 8.0,
    max_threads: int = 20,
) -> list[dict]:
    """
    Testa a lista de caminhos sensiveis contra a URL base, em paralelo.

    Args:
        base_url: raiz do site, ex "https://exemplo.com" (sem barra no fim)
        caminhos: lista a testar (usa CAMINHOS_SENSIVEIS por padrao)
        timeout: tempo maximo por requisicao
        max_threads: requisicoes simultaneas

    Returns:
        Lista de dicts dos caminhos que responderam com status interessante,
        ordenada por status (200 primeiro) e depois pelo caminho.
    """
    if caminhos is None:
        caminhos = CAMINHOS_SENSIVEIS

    base_url = base_url.rstrip("/")
    achados = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futuros = [
            executor.submit(_testar_caminho, base_url, caminho, timeout)
            for caminho in caminhos
        ]
        for futuro in as_completed(futuros):
            resultado = futuro.result()
            if resultado is not None:
                achados.append(resultado)

    return sorted(achados, key=lambda item: (item["status"], item["caminho"]))


if __name__ == "__main__":
    # Silencia o aviso de "certificado nao verificado" - a gente desligou
    # a verificacao de proposito pra nao perder alvo por cert quebrado.
    requests.packages.urllib3.disable_warnings()

    alvo = input("Digite a URL base (ex: https://exemplo.com): ").strip().rstrip("/")
    confirmacao = (
        input("Confirma que tem autorizacao para sondar este site? (sim/nao): ")
        .strip()
        .lower()
    )

    if confirmacao != "sim":
        print("Verificacao cancelada.")
    else:
        print(f"\nTestando {len(CAMINHOS_SENSIVEIS)} caminhos sensiveis em {alvo}...")
        resultado = enumerar(alvo)
        if not resultado:
            print("Nenhum dos caminhos testados respondeu de forma interessante.")
        else:
            print(f"\n{len(resultado)} caminho(s) encontrado(s):\n")
            for item in resultado:
                print(f"  [{item['significado']}] /{item['caminho']}  ({item['tamanho']} bytes)")
