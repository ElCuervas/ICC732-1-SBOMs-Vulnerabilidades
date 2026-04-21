FROM python:3.11-slim

# ── Sistema base ──────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Grype (escaner de vulnerabilidades) ──────────────────────────────────────
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin

# ── Syft (generador de SBOMs alternativo / validacion) ───────────────────────
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin

# ── Dependencias Python ───────────────────────────────────────────────────────
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir \
    -r /tmp/requirements.txt \
    pandas \
    matplotlib \
    seaborn \
    jupyter \
    ipykernel \
    && python -m ipykernel install --sys-prefix --name sbom --display-name "Python (sbom)"

# ── Actualizar BD de Grype al construir la imagen ────────────────────────────
# (se puede omitir si no hay acceso a internet al buildear;
#  en ese caso ejecutar: grype db update  al abrir el contenedor)
RUN grype db update || echo "grype db update falló (sin internet), ejecutar manualmente"

WORKDIR /workspace
