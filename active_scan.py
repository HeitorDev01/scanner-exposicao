"""
active_scan.py

Modulo de verificacao ATIVA de portas - diferente de tudo que fizemos
ate agora nos outros modulos. Aqui a gente realmente conecta no
servidor do alvo pra confirmar se uma porta esta aberta, em vez de
so consultar um banco de dados publico de terceiros.

IMPORTANTE - isso muda a natureza legal do que estamos fazendo:
Os modulos anteriores (crt.sh, headers HTTP, Shodan InternetDB) so
consultavam informacao PUBLICA ja existente - nunca mandavam nada
direto pro servidor do alvo com a intencao de sondar ele. Aqui SIM
estamos mandando trafego pro alvo pra testar as portas. Por isso,
so use isso em dominios que voce tem autorizacao explicita pra
verificar.
"""

import socket


# As portas mais comuns de se verificar num recon basico - a mesma
# lista que ja usamos no translator.py pra explicar o que cada uma
# significa.
PORTAS_COMUNS = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080]


def verificar_portas(ip: str, portas: list[int] = None, timeout: float = 1.5) -> list[int]:
    """
    Tenta conectar em cada porta da lista e devolve quais responderam
    como abertas.

    Isso e chamado de "TCP connect scan" - a forma mais simples e
    menos invasiva de verificar porta (e essencialmente o mesmo que
    um navegador faz ao tentar acessar um servico, so que testando
    varias portas em vez de uma so).

    Args:
        ip: o IP do servidor a verificar
        portas: lista de portas a testar (usa PORTAS_COMUNS por padrao)
        timeout: quanto tempo esperar resposta por porta, em segundos

    Returns:
        Lista das portas que responderam como abertas.
    """
    if portas is None:
        portas = PORTAS_COMUNS

    portas_abertas = []

    for porta in portas:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            resultado = sock.connect_ex((ip, porta))
            if resultado == 0:
                portas_abertas.append(porta)
        finally:
            sock.close()

    return portas_abertas


if __name__ == "__main__":
    ip_alvo = input("Digite o IP a verificar (voce precisa ter autorizacao): ").strip()
    confirmacao = (
        input("Confirma que tem autorizacao para verificar este IP? (sim/nao): ")
        .strip()
        .lower()
    )

    if confirmacao != "sim":
        print("Verificacao cancelada.")
    else:
        print(f"\nVerificando {len(PORTAS_COMUNS)} portas comuns em {ip_alvo}...")
        abertas = verificar_portas(ip_alvo)
        if abertas:
            print(f"Portas abertas encontradas: {abertas}")
        else:
            print("Nenhuma das portas comuns testadas respondeu como aberta.")