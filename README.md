# SMOBs

Generacion de SBOMs y analisis de vulnerabilidades para repositorios GitHub.

---

## Inicio rapido con Dev Container (recomendado)

Requiere [Docker](https://www.docker.com/get-started) y [VS Code](https://code.visualstudio.com/)
con la extension [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers).

```bash
git clone https://github.com/ElCuervas/ICC732-1-SBOMs-Vulnerabilidades
```

En VS Code: `Ctrl+Shift+P` -> **Dev Containers: Reopen in Container**

El contenedor instala automaticamente Python 3.11, Grype, Syft y Jupyter.
La primera vez tarda 3-5 minutos.

---

## Inicio rapido sin Dev Container

```bash
# 1. Instalar Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b ~/.local/bin
grype db update

# 2. Instalar dependencias Python
pip install -r requirements.txt

# 3. Verificar entorno
python analizador_project/scripts/repo_analyzer.py --diagnose --repos-dir .
```

---

## Uso del codigo

### Analisis completo

```bash
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx (tu token)

python analizador_project/scripts/main.py --org encode --output-root ./workspace
```

**Paso 1 - Extraccion**: consulta la API de GitHub, filtra repositorios activos
(ultimo push <= 30 dias), los clona en `workspace/repos/encode/` y genera `manifest.json`.

**Paso 2 - Analisis**: para cada repo genera un SBOM (CycloneDX 1.4 JSON) con
`SBOMGenerator`, luego pasa el SBOM a Grype para detectar vulnerabilidades reales
contra su BD (NVD, GitHub Advisories, Alpine SecDB, etc.).

Archivos generados:
```
workspace/
  repos/encode/
    <repo>/                  <- repos clonados
    manifest.json            <- metadatos de repos
  sboms/encode/
    sbom_<repo>.cyclonedx.json
    <repo>-grype-raw.json    <- output original de Grype
  reports/encode/
    analysis_report.json     <- reporte completo
    analysis_report.csv      <- tabla de repos
    vulnerabilities.csv      <- tabla de CVEs encontrados
```

### Solo extraccion

```bash
python analizador_project/scripts/main.py --org encode --output-root ./workspace --only extract
```

### Solo analisis (repos ya clonados)

```bash
python analizador_project/scripts/main.py --org encode --output-root ./workspace --only analyze
```

### Verificar que Grype esta listo

```bash
python analizador_project/scripts/main.py --diagnose --org encode --output-root ./workspace
```

### Todas las opciones

```
--org              Organizacion GitHub (requerido)
--output-root      Carpeta raiz del workspace (default: ./workspace)
--only             extract | analyze  (default: ambos pasos)
--token            GitHub token (o variable de entorno GITHUB_TOKEN)
--days             Ventana de actividad en dias (default: 30)
--max-repos        Maximo de repos a procesar (default: 50)
--depth            Profundidad del git clone (default: 1)
--grype-timeout    Timeout por repo en segundos (default: 120)
--diagnose         Verificar Grype instalado y BD lista
--verbose          Logging detallado
```

---

## Notebook de analisis

El notebook `analisis.ipynb` consume los archivos del analizador y produce
el analisis cuantitativo. Debe ejecutarse desde la misma carpeta donde esta `workspace/`.

```bash
jupyter notebook analisis.ipynb
# o desde VS Code: abrir el archivo .ipynb y seleccionar kernel Python 3
```

Cambia `ORG = 'encode'` en la celda de configuracion si usaste otra organizacion.

El notebook produce:
- Estadisticas descriptivas de dependencias
- Graficos de componentes, severidad y CVSS
- Risk Score y mapa de calor por repositorio
- Tabla de priorizacion de remediacion

---

## Estructura del proyecto

```
analizador_project/scripts/
  main.py            <- orquestador del analizador
  repo_extractor.py  <- RepoExtractor: GitHub API + git clone
  sbom_generator.py  <- SBOMGenerator: manifiestos -> CycloneDX 1.4 JSON
  repo_analyzer.py   <- RepoAnalyzer:  SBOM -> Grype -> reportes
.devcontainer/
  Dockerfile         <- Python 3.11 + Grype + Syft + Jupyter
  devcontainer.json
analisis.ipynb
requirements.txt
```

---

## Requisitos

- Python 3.11+
- Grype CLI — https://github.com/anchore/grype
- Git
- GitHub token con scope `public_repo` (evita el rate limit de 60 req/h de la API publica)
