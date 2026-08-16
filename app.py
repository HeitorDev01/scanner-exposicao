"""
app.py

Interface web (Flask) do scanner. Rode `python app.py` e abra
http://127.0.0.1:5000.

Cada scan roda numa thread separada; a tela faz polling em /status a cada
1,5s pra mostrar o progresso ao vivo sem travar o navegador.
"""

import os
import uuid
import threading

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file,
    abort,
    redirect,
    url_for,
)

from gerar_relatorio import coletar_dados, gerar_pdf, normalizar_dominio
from translator import explicar_porta


app = Flask(__name__)

# Subpasta onde os PDFs gerados ficam.
PASTA_RELATORIOS = os.path.join(os.path.dirname(__file__), "relatorios")

# Estado dos scans em memoria, por job_id. Some quando o servidor reinicia.
#   { "status": "rodando"|"concluido"|"erro", "log": [...], "dados": {...},
#     "pdf": str, "erro": str, "dominio": str }
JOBS: dict[str, dict] = {}


def _rodar_scan(job_id: str, dominio: str, autorizado: bool) -> None:
    """Executa o scan numa thread e vai preenchendo o JOBS[job_id]."""
    job = JOBS[job_id]

    def log(mensagem):
        job["log"].append(str(mensagem))

    try:
        dados = coletar_dados(dominio, autorizado_para_scan_ativo=autorizado, log=log)

        os.makedirs(PASTA_RELATORIOS, exist_ok=True)
        nome_pdf = f"relatorio_{dominio.replace('.', '_')}_{job_id[:8]}.pdf"
        caminho_pdf = os.path.join(PASTA_RELATORIOS, nome_pdf)
        gerar_pdf(dados, caminho_pdf)

        job["dados"] = dados
        job["pdf"] = caminho_pdf
        job["status"] = "concluido"
        log("Relatorio gerado. Redirecionando...")
    except Exception as erro:  # nao deixa a thread morrer em silencio
        job["status"] = "erro"
        job["erro"] = str(erro)
        log(f"ERRO: {erro}")


@app.route("/")
def index():
    """Tela inicial com o formulario."""
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    """Inicia um scan em background e devolve o id do job."""
    entrada = (request.form.get("dominio") or "").strip()
    autorizado = request.form.get("autorizado") == "sim"

    if not entrada:
        return jsonify({"erro": "Informe um dominio."}), 400

    dominio = normalizar_dominio(entrada)

    job_id = uuid.uuid4().hex
    JOBS[job_id] = {
        "status": "rodando",
        "log": [],
        "dados": None,
        "pdf": None,
        "erro": None,
        "dominio": dominio,
        "autorizado": autorizado,
    }

    thread = threading.Thread(
        target=_rodar_scan, args=(job_id, dominio, autorizado), daemon=True
    )
    thread.start()

    return jsonify({"job_id": job_id, "dominio": dominio})


@app.route("/status/<job_id>")
def status(job_id: str):
    """Devolve o estado atual do scan (pra tela ir atualizando)."""
    job = JOBS.get(job_id)
    if job is None:
        return jsonify({"erro": "job nao encontrado"}), 404

    return jsonify(
        {
            "status": job["status"],
            "log": job["log"],
            "erro": job["erro"],
        }
    )


@app.route("/resultado/<job_id>")
def resultado(job_id: str):
    """Pagina final com os resultados em tabelas."""
    job = JOBS.get(job_id)
    if job is None or job["status"] != "concluido":
        # ainda rodando ou inexistente -> manda pra home
        return redirect(url_for("index"))

    dados = job["dados"]

    # Enriquece as portas com a explicacao (o template so exibe).
    portas = [
        {
            "porta": item["porta"],
            "banner": item["banner"],
            "significado": explicar_porta(item["porta"]),
        }
        for item in dados["portas"]
    ]

    return render_template(
        "resultado.html", job_id=job_id, dados=dados, portas=portas
    )


@app.route("/download/<job_id>")
def download(job_id: str):
    """Entrega o PDF do scan pra download."""
    job = JOBS.get(job_id)
    if job is None or not job.get("pdf") or not os.path.exists(job["pdf"]):
        abort(404)

    nome_amigavel = f"relatorio_{job['dominio'].replace('.', '_')}.pdf"
    return send_file(job["pdf"], as_attachment=True, download_name=nome_amigavel)


if __name__ == "__main__":
    print("Scanner de Exposicao - interface web")
    print("Abra no navegador: http://127.0.0.1:5000")
    # debug=False de proposito: com o reloader ligado, as threads de scan
    # podem se perder quando o Flask reinicia sozinho.
    app.run(host="127.0.0.1", port=5000, debug=False)
