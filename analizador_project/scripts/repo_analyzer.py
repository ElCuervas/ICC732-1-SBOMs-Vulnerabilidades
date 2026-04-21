"""
Clase responsable de analizar repositorios ya descargados por RepoExtractor.

Flujo:
  1. Lee el manifiesto JSON generado por RepoExtractor (o escanea la carpeta).
  2. Para cada repositorio invoca SBOMGenerator y obtiene el SBOM.
  3. Pasa el SBOM a Grype CLI para detectar vulnerabilidades reales contra
     su base de datos (NVD + GitHub Advisories + Alpine SecDB + ...).
  4. Normaliza el output de Grype al mismo dataclass VulnerabilityFinding.
  5. Exporta:
       - SBOMs individuales (.cyclonedx.json)   en --sboms-dir
       - Raw Grype JSON    (*-grype-raw.json)    en --sboms-dir
       - Reporte consolidado JSON               en --output
       - Reporte consolidado CSV                en --output

Prerequisito:
    Grype debe estar instalado y en el PATH.
    Instalacion rapida:
        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
            | sh -s -- -b /usr/local/bin
        grype db update

Uso standalone:
    python repo_analyzer.py --repos-dir ./repos/encode --sboms-dir ./sboms --output ./reports
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sbom_generator import SBOMGenerator, SBOMResult, Component

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  Dataclasses de resultados  (sin cambios — el notebook y los CSV dependen de esto)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class VulnerabilityFinding:
    cve_id: str
    package: str
    version_found: str
    version_fix: str
    severity: str
    cvss: float
    vuln_type: str
    cwe: str
    description: str
    repo: str

@dataclass
class RepoAnalysisResult:
    repo_name: str
    repo_path: str
    ecosystem: str
    n_components: int
    n_direct: int
    n_optional: int
    n_vulnerabilities: int
    risk_score: float
    risk_level: str
    vulnerabilities: list[VulnerabilityFinding] = field(default_factory=list)
    sbom_path: str = ""
    errors: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
#  Clase principal
# ─────────────────────────────────────────────────────────────────────────────

class RepoAnalyzer:
    """
    Analiza repositorios clonados por RepoExtractor usando Grype para
    detectar vulnerabilidades reales en lugar de una BD hardcodeada.

    Parameters
    ----------
    repos_dir : str | Path
        Carpeta raiz con los repositorios (cada subcarpeta = un repo).
        Debe contener un manifest.json (generado por RepoExtractor) o
        simplemente subdirectorios con repos clonados.
    sboms_dir : str | Path
        Carpeta donde se guardaran los SBOMs y los JSON raw de Grype.
    output_dir : str | Path
        Carpeta donde se guardaran los reportes finales.
    grype_timeout : int
        Segundos de timeout para cada ejecucion de Grype. Default: 120.
    """

    SEVERITY_WEIGHTS = {"CRITICAL": 4.0, "HIGH": 2.5, "MEDIUM": 1.0, "LOW": 0.3}

    def __init__(
        self,
        repos_dir: str | Path,
        sboms_dir: str | Path = "./sboms",
        output_dir: str | Path = "./reports",
        grype_timeout: int = 120,
    ) -> None:
        self.repos_dir     = Path(repos_dir)
        self.sboms_dir     = Path(sboms_dir)
        self.output_dir    = Path(output_dir)
        self.grype_timeout = grype_timeout
        self.results: list[RepoAnalysisResult] = []

        self._grype_bin = self._find_grype()

    # ── Verificacion de Grype ────────────────────────────────────────────────

    @staticmethod
    def _find_grype() -> str:
        """
        Localiza el binario de Grype en el PATH.
        Lanza RuntimeError con instrucciones de instalacion si no lo encuentra.
        """
        path = shutil.which("grype")
        if path:
            logger.info("Grype encontrado: %s", path)
            return path

        raise RuntimeError(
            "Grype no esta instalado o no esta en el PATH.\n"
            "Instalalo con:\n"
            "  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh"
            " | sh -s -- -b /usr/local/bin\n"
            "  grype db update"
        )

    def _grype_version(self) -> str:
        """Retorna la version de Grype instalada (para logs y reportes)."""
        try:
            out = subprocess.run(
                [self._grype_bin, "version", "--output", "json"],
                capture_output=True, text=True, timeout=15,
            )
            data = json.loads(out.stdout)
            return data.get("version", "unknown")
        except Exception:
            return "unknown"

    def diagnose(self) -> bool:
        """
        Verifica que Grype este disponible y su BD este actualizada.
        Imprime el resultado en consola. Retorna True si todo esta OK.
        """
        print("\n=== Diagnostico de entorno ===")
        ok = True

        # Grype binario
        try:
            ver = self._grype_version()
            print(f"  Grype CLI: {ver}")
        except Exception as e:
            print(f"  ERROR Grype CLI: {e}")
            ok = False

        # Base de datos Grype
        try:
            out = subprocess.run(
                [self._grype_bin, "db", "status"],
                capture_output=True, text=True, timeout=15,
            )
            lines = (out.stdout + out.stderr).strip().splitlines()
            status_line = next(
                (l for l in lines if "Status" in l or "status" in l),
                lines[0] if lines else "desconocido"
            )
            print(f"  Grype DB : {status_line.strip()}")
        except Exception as e:
            print(f"  ERROR Grype DB: {e}")
            ok = False

        print("=" * 30)
        return ok

    # ── Descubrimiento de repos ───────────────────────────────────────────────

    def _discover_repos(self) -> list[Path]:
        """
        Retorna lista de rutas de repos a analizar.
        Busca manifest.json primero; si no existe, enumera subdirectorios.
        """
        manifest = self.repos_dir / "manifest.json"
        if manifest.exists():
            data  = json.loads(manifest.read_text())
            repos = [Path(r["local_path"]) for r in data["repos"]
                     if r.get("local_path") and Path(r["local_path"]).exists()]
            logger.info(
                "Manifiesto encontrado: %d repos listados, %d en disco",
                len(data["repos"]), len(repos),
            )
            return repos

        # Fallback: escanear subcarpetas
        repos = [p for p in sorted(self.repos_dir.iterdir())
                 if p.is_dir() and not p.name.startswith(".")]
        logger.info("Sin manifiesto, %d subdirectorios encontrados en %s",
                    len(repos), self.repos_dir)
        return repos

    # ── Grype: escaneo real ──────────────────────────────────────────────────

    def _run_grype(self, sbom_path: Path, repo_name: str) -> list[VulnerabilityFinding]:
        """
        Ejecuta Grype sobre el SBOM generado por SBOMGenerator y
        retorna una lista de VulnerabilityFinding normalizados.

        Grype recibe el SBOM en formato CycloneDX JSON (sbom:<ruta>),
        lo cruza contra su BD (NVD, GitHub Advisories, Alpine SecDB, etc.)
        y devuelve un JSON con todos los matches.

        El JSON raw se guarda en sboms_dir para debug y para el notebook.
        """
        self.sboms_dir.mkdir(parents=True, exist_ok=True)
        raw_path = self.sboms_dir / f"{repo_name}-grype-raw.json"

        cmd = [
            self._grype_bin,
            f"sbom:{sbom_path}",   # apuntar al SBOM ya generado por SBOMGenerator
            "--output", "json",
            "--quiet",             # suprime la barra de progreso en stderr
        ]

        logger.info("  Ejecutando Grype en %s...", repo_name)
        logger.debug("  Comando: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.grype_timeout,
            )
        except subprocess.TimeoutExpired:
            msg = f"Grype timeout ({self.grype_timeout}s) en {repo_name}"
            logger.error("  %s", msg)
            return []
        except Exception as e:
            logger.error("  Error ejecutando Grype en %s: %s", repo_name, e)
            return []

        # returncode=0  -> ok sin vulns
        # returncode=1  -> ok con vulns encontradas (comportamiento normal de Grype)
        # cualquier otro -> error real
        if result.returncode not in (0, 1):
            logger.error(
                "  Grype termino con codigo %d en %s: %s",
                result.returncode, repo_name, result.stderr[:200],
            )
            return []

        if not result.stdout.strip():
            logger.warning("  Grype no produjo output para %s", repo_name)
            return []

        # Guardar JSON raw para debug y notebook
        raw_path.write_text(result.stdout, encoding="utf-8")
        logger.info("  Raw Grype guardado: %s", raw_path)

        return self._parse_grype_output(result.stdout, repo_name)

    def _parse_grype_output(self, grype_json: str, repo_name: str) -> list[VulnerabilityFinding]:
        """
        Convierte el JSON de Grype al dataclass VulnerabilityFinding.

        Estructura relevante del JSON de Grype:
        {
          "matches": [
            {
              "vulnerability": {
                "id":          "CVE-2021-23337",
                "severity":    "High",
                "description": "...",
                "fix":         { "versions": ["4.17.21"], "state": "fixed" },
                "cvss":        [ { "metrics": { "baseScore": 7.2 } } ],
                "cwes":        [ "CWE-78" ]
              },
              "artifact": {
                "name":    "lodash",
                "version": "4.17.15",
                "type":    "npm"
              },
              "matchDetails": [ { "type": "exact-direct-match" } ]
            }
          ]
        }
        """
        try:
            data = json.loads(grype_json)
        except json.JSONDecodeError as e:
            logger.error("  Error parseando JSON de Grype: %s", e)
            return []

        matches = data.get("matches", [])
        logger.info("  Grype encontro %d matches en %s", len(matches), repo_name)

        findings: list[VulnerabilityFinding] = []

        for match in matches:
            vuln     = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            cve_id  = vuln.get("id", "UNKNOWN")
            pkg     = artifact.get("name", "unknown")
            version = artifact.get("version", "?")

            # Severity: Grype la devuelve capitalizada ("High", "Critical", etc.)
            severity_raw = vuln.get("severity", "Unknown").upper()
            severity = severity_raw if severity_raw in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "LOW"

            # CVSS score: tomar el mayor disponible entre todos los entries
            cvss_score = self._extract_cvss(vuln)

            # Version de correccion
            fix_info    = vuln.get("fix", {})
            fix_versions = fix_info.get("versions", [])
            version_fix  = fix_versions[0] if fix_versions else "N/A"

            # CWE
            cwe = self._extract_cwe(match)

            # Tipo de match (para vuln_type)
            match_details = match.get("matchDetails", [{}])
            vuln_type = match_details[0].get("type", "dependency") if match_details else "dependency"

            description = vuln.get("description", "")
            if len(description) > 300:
                description = description[:297] + "..."

            findings.append(VulnerabilityFinding(
                cve_id=cve_id,
                package=pkg,
                version_found=version,
                version_fix=version_fix,
                severity=severity,
                cvss=cvss_score,
                vuln_type=vuln_type,
                cwe=cwe,
                description=description,
                repo=repo_name,
            ))

        return findings

    @staticmethod
    def _extract_cvss(vuln: dict) -> float:
        """
        Extrae el CVSS score mas alto disponible del objeto vulnerability de Grype.
        Grype puede incluir scores de CVSS v2 y v3; preferimos el mayor.
        """
        best = 0.0
        for entry in vuln.get("cvss", []):
            metrics = entry.get("metrics", {})
            for key in ("baseScore", "score"):
                val = metrics.get(key)
                if isinstance(val, (int, float)) and val > best:
                    best = float(val)
        # Fallback en relatedVulnerabilities
        if best == 0.0:
            for rel in vuln.get("relatedVulnerabilities", []):
                for entry in rel.get("cvss", []):
                    metrics = entry.get("metrics", {})
                    for key in ("baseScore", "score"):
                        val = metrics.get(key)
                        if isinstance(val, (int, float)) and val > best:
                            best = float(val)
        return round(best, 1)

    @staticmethod
    def _extract_cwe(match: dict) -> str:
        """Extrae el primer CWE disponible del match de Grype."""
        vuln = match.get("vulnerability", {})
        cwes = vuln.get("cwes", [])
        if cwes:
            return cwes[0]
        for rel in vuln.get("relatedVulnerabilities", []):
            rel_cwes = rel.get("cwes", [])
            if rel_cwes:
                return rel_cwes[0]
        return "N/A"

    # ── Risk score ────────────────────────────────────────────────────────────

    def _compute_risk_score(
        self, findings: list[VulnerabilityFinding], n_components: int
    ) -> tuple[float, str]:
        """
        Risk Score = suma(cvss * weight_severity) / max(n_components, 1) * 2
        Capped a 100.
        """
        if not findings:
            return 0.0, "NINGUNO"

        weighted = sum(
            f.cvss * self.SEVERITY_WEIGHTS.get(f.severity, 1.0) for f in findings
        )
        score = min(round(weighted / max(n_components, 1) * 2, 2), 100.0)

        if score >= 20:   level = "CRITICO"
        elif score >= 10: level = "ALTO"
        elif score >= 4:  level = "MEDIO"
        else:             level = "BAJO"

        return score, level

    # ── Analisis de un repo ───────────────────────────────────────────────────

    def analyze_repo(self, repo_path: Path) -> RepoAnalysisResult:
        """
        Analiza un unico repositorio:
          1. Genera SBOM con SBOMGenerator.
          2. Pasa el SBOM a Grype para detectar vulnerabilidades reales.
          3. Calcula risk score.
        """
        logger.info("-" * 55)
        logger.info("Analizando: %s", repo_path.name)

        # Paso 1: Generar SBOM
        gen = SBOMGenerator(repo_path, output_dir=self.sboms_dir)
        try:
            sbom_result, sbom_path = gen.run()
        except FileNotFoundError as e:
            logger.error("  %s", e)
            return RepoAnalysisResult(
                repo_name=repo_path.name, repo_path=str(repo_path),
                ecosystem="unknown", n_components=0, n_direct=0,
                n_optional=0, n_vulnerabilities=0, risk_score=0.0,
                risk_level="NINGUNO", errors=[str(e)],
            )

        components = sbom_result.components
        n_direct   = sum(1 for c in components if c.scope == "required")
        n_optional = sum(1 for c in components if c.scope == "optional")

        # Paso 2: Escanear con Grype
        if not components:
            logger.info("  Sin componentes en SBOM, omitiendo Grype")
            findings = []
        else:
            findings = self._run_grype(sbom_path, repo_path.name)

        sev_counts = Counter(f.severity for f in findings)
        if findings:
            logger.info(
                "  Vulnerabilidades: CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d",
                sev_counts.get("CRITICAL", 0), sev_counts.get("HIGH", 0),
                sev_counts.get("MEDIUM", 0),   sev_counts.get("LOW", 0),
            )
        else:
            logger.info("  Sin vulnerabilidades detectadas")

        # Paso 3: Risk Score
        risk_score, risk_level = self._compute_risk_score(findings, len(components))

        return RepoAnalysisResult(
            repo_name=repo_path.name,
            repo_path=str(repo_path),
            ecosystem=sbom_result.ecosystem,
            n_components=len(components),
            n_direct=n_direct,
            n_optional=n_optional,
            n_vulnerabilities=len(findings),
            risk_score=risk_score,
            risk_level=risk_level,
            vulnerabilities=findings,
            sbom_path=str(sbom_path),
            errors=sbom_result.errors,
        )

    # ── Analisis de todos los repos ───────────────────────────────────────────

    def analyze_all(self) -> list[RepoAnalysisResult]:
        """
        Descubre y analiza todos los repositorios en repos_dir.
        Retorna lista de RepoAnalysisResult ordenada por risk_score desc.
        """
        repo_paths = self._discover_repos()
        if not repo_paths:
            logger.warning("No se encontraron repositorios en %s", self.repos_dir)
            return []

        logger.info("=" * 55)
        logger.info("Grype version  : %s", self._grype_version())
        logger.info("Analizando %d repositorios...", len(repo_paths))
        logger.info("=" * 55)

        results = []
        for repo_path in repo_paths:
            result = self.analyze_repo(repo_path)
            results.append(result)

        results.sort(key=lambda r: r.risk_score, reverse=True)
        self.results = results
        return results

    # ── Exportacion ──────────────────────────────────────────────────────────

    def save_reports(self) -> dict[str, Path]:
        """
        Guarda los reportes consolidados en output_dir:
          - analysis_report.json
          - analysis_report.csv
          - vulnerabilities.csv
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # JSON completo
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "grype_version": self._grype_version(),
            "total_repos":  len(self.results),
            "total_vulns":  sum(r.n_vulnerabilities for r in self.results),
            "repos": [
                {**{k: v for k, v in asdict(r).items() if k != "vulnerabilities"},
                 "vulnerabilities": [asdict(f) for f in r.vulnerabilities]}
                for r in self.results
            ],
        }
        json_path = self.output_dir / "analysis_report.json"
        json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
        logger.info("Reporte JSON: %s", json_path)

        # CSV de repos
        csv_repos = self.output_dir / "analysis_report.csv"
        repo_fields = [
            "repo_name", "ecosystem", "n_components", "n_direct",
            "n_optional", "n_vulnerabilities", "risk_score", "risk_level",
        ]
        with open(csv_repos, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=repo_fields)
            w.writeheader()
            for r in self.results:
                w.writerow({k: getattr(r, k) for k in repo_fields})
        logger.info("Reporte CSV repos: %s", csv_repos)

        # CSV de vulnerabilidades
        csv_vulns = self.output_dir / "vulnerabilities.csv"
        vuln_fields = [
            "repo", "cve_id", "package", "version_found", "version_fix",
            "severity", "cvss", "vuln_type", "cwe", "description",
        ]
        with open(csv_vulns, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=vuln_fields)
            w.writeheader()
            for r in self.results:
                for vuln in r.vulnerabilities:
                    w.writerow(asdict(vuln))
        logger.info("Reporte CSV vulns: %s", csv_vulns)

        return {"json": json_path, "csv_repos": csv_repos, "csv_vulns": csv_vulns}

    def print_summary(self) -> None:
        """Imprime un resumen en consola."""
        if not self.results:
            print("Sin resultados.")
            return

        total_vulns = sum(r.n_vulnerabilities for r in self.results)
        total_comps = sum(r.n_components      for r in self.results)
        all_findings = [f for r in self.results for f in r.vulnerabilities]
        sev_cnt = Counter(f.severity for f in all_findings)

        print("\n" + "=" * 60)
        print("   RESUMEN DE ANALISIS  (Grype)")
        print("=" * 60)
        print(f"  Repositorios analizados : {len(self.results)}")
        print(f"  Componentes totales     : {total_comps}")
        print(f"  Vulnerabilidades totales: {total_vulns}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            n = sev_cnt.get(sev, 0)
            if n:
                bar = "#" * min(n, 40)
                print(f"    {bar} {sev}: {n}")
        print()
        print(f"  {'REPOSITORIO':<25} {'COMPS':>5} {'CVEs':>5}  RIESGO")
        print(f"  {'-'*25} {'-'*5} {'-'*5}  {'-'*20}")
        for r in self.results:
            print(f"  {r.repo_name:<25} {r.n_components:>5} {r.n_vulnerabilities:>5}  "
                  f"{r.risk_level}  (score={r.risk_score})")
        print("=" * 60)

    # ── Flujo principal ───────────────────────────────────────────────────────

    def run(self) -> dict[str, Path]:
        """Ejecuta analyze_all() + save_reports() + print_summary()."""
        self.analyze_all()
        paths = self.save_reports()
        self.print_summary()
        return paths


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="repo_analyzer",
        description="Analiza repositorios clonados: genera SBOMs y escanea con Grype.",
    )
    p.add_argument("--repos-dir",     required=True,
                   help="Carpeta con los repos clonados (o que contiene manifest.json)")
    p.add_argument("--sboms-dir",     default="./sboms",
                   help="Carpeta de salida para SBOMs y raw Grype (default: ./sboms)")
    p.add_argument("--output",        default="./reports",
                   help="Carpeta de salida para reportes (default: ./reports)")
    p.add_argument("--grype-timeout", type=int, default=120,
                   help="Timeout en segundos por ejecucion de Grype (default: 120)")
    p.add_argument("--diagnose",      action="store_true",
                   help="Verificar que Grype esta instalado y su BD lista, luego salir")
    p.add_argument("--verbose",       action="store_true",
                   help="Logging detallado (DEBUG)")
    return p


def main(argv: list[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    analyzer = RepoAnalyzer(
        repos_dir=args.repos_dir,
        sboms_dir=args.sboms_dir,
        output_dir=args.output,
        grype_timeout=args.grype_timeout,
    )

    if args.diagnose:
        analyzer.diagnose()
        return

    paths = analyzer.run()
    print("\nArchivos generados:")
    for name, path in paths.items():
        print(f"   {name:<12}: {path}")


if __name__ == "__main__":
    main()
