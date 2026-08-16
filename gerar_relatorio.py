"""
gerar_relatorio.py

Junta todos os modulos (crt.sh, headers, Shodan, CVEs, port scan, dir enum,
subdominios, TLS) e gera o relatorio em PDF.

As checagens ativas (port scan, dir enum, subdominios) so rodam com
autorizacao confirmada; as leves (headers, TLS) rodam sempre.
"""

import socket

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import cm
import requests

from subdomain_finder import find_subdomains
from http_info import resolve_ip, get_http_headers, get_internetdb_info
from translator import explicar_porta, traduzir_cves
from port_scanner import escanear as escanear_portas
from dir_enum import enumerar as enumerar_caminhos
from subdomain_probe import sondar_lista
from tls_headers import analisar_headers, analisar_tls

# Varios modulos ativos usam verify=False (pra nao perder alvo por
# certificado quebrado). Isso silencia o aviso repetido do urllib3.
requests.packages.urllib3.disable_warnings()


def coletar_dados(dominio: str, autorizado_para_scan_ativo: bool = False, log=print) -> dict:
    """
    Roda todos os modulos e junta tudo num dicionario so.

    Se alguma parte falhar (site fora do ar, Shodan sem resposta...), o
    programa nao trava - registra que aquela parte nao pode ser verificada
    e segue. Um relatorio parcial e melhor que nenhum.

    Args:
        dominio: o dominio a verificar
        autorizado_para_scan_ativo: so faz as checagens ativas (port scan,
            enum de diretorios, sondagem de subdominios) se isso for True.
        log: funcao pra onde mandar as mensagens de progresso. Por padrao
            e o print() (usado pelo CLI). A interface web passa a propria,
            que joga as mensagens pra tela ao vivo.
    """
    # --- Passivo: sempre roda (nao toca no alvo com intencao de sondar) ---
    log("Buscando subdominios (crt.sh)...")
    try:
        subdominios = find_subdomains(dominio)
    except requests.exceptions.RequestException as erro:
        log(f"  Nao consegui buscar subdominios: {erro}")
        subdominios = []

    log("Resolvendo IP...")
    try:
        ip = resolve_ip(dominio)
    except socket.gaierror as erro:
        log(f"  Nao consegui resolver o IP: {erro}")
        ip = None

    log("Buscando headers HTTP...")
    headers = get_http_headers(dominio)  # ja devolve {} sozinho se falhar
    if not headers:
        log("  O site nao respondeu (nem HTTPS nem HTTP) ou nao expos headers.")

    portas_passivas = []
    cves_brutos = []
    if ip:
        log("Consultando Shodan InternetDB...")
        try:
            info = get_internetdb_info(ip)
            portas_passivas = info.get("ports", [])
            cves_brutos = info.get("vulns", [])
        except requests.exceptions.RequestException as erro:
            log(f"  Nao consegui consultar o InternetDB: {erro}")

    # --- Leve: analise de headers e TLS (uma conexao, igual navegador) ---
    log("Analisando headers de seguranca...")
    headers_seg = analisar_headers(headers)

    log("Analisando configuracao TLS...")
    tls = analisar_tls(dominio)

    # --- Ativo: so com autorizacao confirmada ---
    portas_ativas = []
    caminhos = []
    subdominios_vivos = []
    if autorizado_para_scan_ativo:
        alvo_scan = ip if ip else dominio
        log("Escaneando portas com banner grabbing (autorizado)...")
        portas_ativas = escanear_portas(alvo_scan)

        log("Enumerando caminhos/arquivos sensiveis (autorizado)...")
        caminhos = enumerar_caminhos(f"https://{dominio}")

        if subdominios:
            log(f"Sondando quais dos {len(subdominios)} subdominios estao vivos (autorizado)...")
            subdominios_vivos = sondar_lista(subdominios)
    else:
        log("  Checagens ativas puladas (sem autorizacao) - usando so dados passivos.")

    # Junta portas passivas (Shodan, so o numero) com ativas (com banner),
    # sem duplicar. O banner do scan ativo tem prioridade sobre o vazio.
    portas_map = {p: "" for p in portas_passivas}
    for item in portas_ativas:
        portas_map[item["porta"]] = item["banner"]
    portas = [
        {"porta": p, "banner": portas_map[p]} for p in sorted(portas_map)
    ]

    cves_traduzidos = []
    if cves_brutos:
        log(f"Traduzindo {len(cves_brutos)} CVE(s) encontrado(s) (pode demorar um pouco)...")
        cves_traduzidos = traduzir_cves(cves_brutos)

    return {
        "dominio": dominio,
        "ip": ip if ip else "nao identificado",
        "subdominios": subdominios,
        "subdominios_vivos": subdominios_vivos,
        "server_header": headers.get("Server", "nao informado"),
        "portas": portas,
        "cves": cves_traduzidos,
        "caminhos": caminhos,
        "headers_seg": headers_seg,
        "tls": tls,
        "scan_ativo_feito": autorizado_para_scan_ativo,
    }


def _tabela_estilo_padrao(tabela: Table) -> Table:
    """Aplica o estilo visual padrao usado em todas as tabelas do relatorio."""
    tabela.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f4f6")]),
            ]
        )
    )
    return tabela


def gerar_pdf(dados: dict, caminho_saida: str) -> None:
    """Gera o PDF com os dados coletados sobre o dominio."""
    doc = SimpleDocTemplate(
        caminho_saida, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm
    )
    styles = getSampleStyleSheet()
    story = []

    # --- Titulo ---
    story.append(Paragraph(f"Relatorio de Exposicao - {dados['dominio']}", styles["Title"]))
    story.append(Spacer(1, 12))

    # --- Resumo ---
    story.append(Paragraph("Resumo", styles["Heading2"]))
    modo = "ativo + passivo" if dados["scan_ativo_feito"] else "somente passivo"
    resumo = (
        f"Tipo de verificacao: {modo}<br/>"
        f"IP encontrado: {dados['ip']}<br/>"
        f"Servidor identificado: {dados['server_header']}<br/>"
        f"Subdominios listados: {len(dados['subdominios'])}"
        f" (vivos: {len(dados['subdominios_vivos'])})<br/>"
        f"Portas abertas conhecidas: {len(dados['portas'])}<br/>"
        f"Caminhos sensiveis encontrados: {len(dados['caminhos'])}<br/>"
        f"Headers de seguranca ausentes: {len(dados['headers_seg']['ausentes'])}<br/>"
        f"Vulnerabilidades conhecidas (CVEs): {len(dados['cves'])}"
    )
    story.append(Paragraph(resumo, styles["Normal"]))
    story.append(Spacer(1, 12))

    # --- Portas (agora com o servico detectado via banner) ---
    if dados["portas"]:
        story.append(Paragraph("Portas abertas", styles["Heading2"]))
        linhas = [["Porta", "O que significa", "Detectado no servidor"]]
        for item in dados["portas"]:
            porta = item["porta"]
            banner = item["banner"] if item["banner"] else "-"
            linhas.append([str(porta), explicar_porta(porta), banner])
        tabela = Table(linhas, colWidths=[1.6 * cm, 7.4 * cm, 6 * cm])
        story.append(_tabela_estilo_padrao(tabela))
        story.append(Spacer(1, 12))

    # --- Caminhos / arquivos sensiveis expostos ---
    if dados["caminhos"]:
        story.append(Paragraph("Arquivos e caminhos sensiveis expostos", styles["Heading2"]))
        story.append(
            Paragraph(
                "Estes caminhos responderam de forma relevante. Um 200 significa "
                "que o recurso abriu publicamente; 401/403 indicam que ele existe "
                "mas esta protegido (ainda assim revela sua presenca).",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 6))
        linhas = [["Caminho", "Situacao", "Tamanho"]]
        for item in dados["caminhos"]:
            linhas.append([f"/{item['caminho']}", item["significado"], f"{item['tamanho']} b"])
        tabela = Table(linhas, colWidths=[7 * cm, 5.5 * cm, 2.5 * cm])
        story.append(_tabela_estilo_padrao(tabela))
        story.append(Spacer(1, 12))

    # --- Configuracao TLS ---
    story.append(Paragraph("Configuracao TLS (HTTPS)", styles["Heading2"]))
    tls = dados["tls"]
    if not tls.get("disponivel"):
        story.append(
            Paragraph(
                f"Nao foi possivel avaliar o TLS deste dominio ({tls.get('erro', 'sem detalhe')}).",
                styles["Normal"],
            )
        )
    else:
        texto_tls = (
            f"Versao aceita: {tls.get('versao') or 'nao identificada'}<br/>"
            f"Cifra: {tls.get('cifra') or 'nao identificada'}<br/>"
            f"Certificado emitido por: {tls.get('emissor') or 'nao identificado'}<br/>"
            f"Certificado expira em: {tls.get('expira_em') or 'nao identificado'}"
        )
        story.append(Paragraph(texto_tls, styles["Normal"]))
        for aviso in tls.get("avisos", []):
            story.append(Paragraph(f"<b>Atencao:</b> {aviso}", styles["Normal"]))
    story.append(Spacer(1, 12))

    # --- Headers de seguranca ---
    story.append(Paragraph("Headers de seguranca", styles["Heading2"]))
    ausentes = dados["headers_seg"]["ausentes"]
    if not ausentes:
        story.append(
            Paragraph(
                "Todos os headers de seguranca avaliados estao presentes. Otimo.",
                styles["Normal"],
            )
        )
    else:
        story.append(
            Paragraph(
                f"{len(ausentes)} header(s) de seguranca ausente(s) - cada um "
                f"deixa uma porta aberta pra um tipo de ataque:",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 6))
        linhas = [["Header ausente", "Risco de nao ter"]]
        for item in ausentes:
            linhas.append([item["header"], item["risco"]])
        tabela = Table(linhas, colWidths=[5 * cm, 10 * cm])
        story.append(_tabela_estilo_padrao(tabela))
    story.append(Spacer(1, 12))

    # --- CVEs ---
    story.append(Paragraph("Vulnerabilidades conhecidas (CVEs)", styles["Heading2"]))
    if dados["cves"]:
        for cve in dados["cves"]:
            texto = f"<b>{cve['id']}</b> (gravidade: {cve['gravidade']})<br/>{cve['descricao']}"
            story.append(Paragraph(texto, styles["Normal"]))
            story.append(Spacer(1, 8))
    else:
        story.append(
            Paragraph(
                "Nenhuma vulnerabilidade foi encontrada nas bases publicas consultadas "
                "(Shodan InternetDB). Isso NAO significa que o site esteja livre de "
                "falhas - significa apenas que nao havia registro publico disponivel "
                "no momento da consulta. Recomenda-se uma analise mais aprofundada "
                "para confirmacao.",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 8))

    # --- Subdominios vivos (o que a sondagem ativa confirmou) ---
    if dados["subdominios_vivos"]:
        story.append(Paragraph("Subdominios vivos", styles["Heading2"]))
        story.append(
            Paragraph(
                "Estes subdominios responderam de verdade (resolvem em DNS). Sao "
                "a superficie de ataque real - vale olhar cada um, principalmente "
                "os de staging/dev/admin esquecidos.",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 6))
        linhas = [["Subdominio", "IP", "HTTP", "Servidor / titulo"]]
        for item in dados["subdominios_vivos"]:
            status = str(item["status"]) if item["status"] is not None else "-"
            contexto = item["servidor"]
            if item["titulo"]:
                contexto = f"{contexto} ({item['titulo']})" if contexto else item["titulo"]
            linhas.append([item["subdominio"], item["ip"], status, contexto or "-"])
        tabela = Table(linhas, colWidths=[6 * cm, 3.5 * cm, 1.5 * cm, 4 * cm])
        story.append(_tabela_estilo_padrao(tabela))
        story.append(Spacer(1, 12))
    elif dados["subdominios"]:
        # tem subdominios listados mas nao sondamos (sem autorizacao) ou nenhum vivo
        story.append(Paragraph("Subdominios encontrados (amostra)", styles["Heading2"]))
        amostra = ", ".join(dados["subdominios"][:20])
        if len(dados["subdominios"]) > 20:
            amostra += f" ... e mais {len(dados['subdominios']) - 20}"
        story.append(Paragraph(amostra, styles["Normal"]))

    doc.build(story)
    print(f"\nRelatorio salvo em: {caminho_saida}")


def normalizar_dominio(entrada: str) -> str:
    """
    Limpa a entrada da pessoa pra extrair so o dominio.

    Aceita que alguem cole a URL inteira (com https://, barra no final,
    caminho depois etc.) e devolve so o dominio puro. Ex:
      "https://www.exemplo.com.br/pagina" -> "www.exemplo.com.br"
    """
    dominio = entrada.strip()

    if "://" in dominio:
        dominio = dominio.split("://", 1)[1]

    dominio = dominio.split("/")[0]  # remove qualquer caminho depois da barra

    return dominio.strip().lower()


if __name__ == "__main__":
    entrada_usuario = input("Digite o dominio (ex: example.com): ")
    dominio_alvo = normalizar_dominio(entrada_usuario)

    if dominio_alvo != entrada_usuario.strip().lower():
        print(f"(usando '{dominio_alvo}' como dominio)")

    resposta = (
        input(
            "\nVoce confirma que tem autorizacao para verificar este dominio "
            "ativamente (port scan, arquivos, subdominios)? (sim/nao): "
        )
        .strip()
        .lower()
    )
    autorizado = resposta == "sim"

    if not autorizado:
        print("Sem autorizacao confirmada - o relatorio vai usar so dados passivos.\n")
    else:
        print()

    dados_coletados = coletar_dados(dominio_alvo, autorizado_para_scan_ativo=autorizado)
    nome_arquivo = f"relatorio_{dominio_alvo.replace('.', '_')}.pdf"
    gerar_pdf(dados_coletados, nome_arquivo)
