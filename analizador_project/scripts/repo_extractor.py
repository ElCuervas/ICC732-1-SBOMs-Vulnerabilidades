"""
repo_extractor.py
=================
Clase responsable de:
  1. Consultar la API de GitHub para listar repositorios activos de una organización.
  2. Clonar cada repositorio en una carpeta local estructurada.
  3. Guardar un manifiesto JSON con metadatos de los repos descargados.

Uso standalone:
    python repo_extractor.py --org encode --output ./repos --days 30
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  Dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RepoInfo:
    """Metadatos de un repositorio de GitHub."""
    name: str
    full_name: str
    clone_url: str
    html_url: str
    description: str
    language: str
    stars: int
    forks: int
    pushed_at: str          # ISO-8601
    default_branch: str
    size_kb: int
    topics: list[str] = field(default_factory=list)
    local_path: Optional[str] = None
    clone_status: str = "pending"   # pending | ok | failed | skipped

    @property
    def pushed_date(self) -> datetime:
        return datetime.fromisoformat(self.pushed_at.replace("Z", "+00:00"))

    def is_active(self, days: int = 30) -> bool:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        return self.pushed_date >= cutoff


# ─────────────────────────────────────────────────────────────────────────────
#  Clase principal
# ─────────────────────────────────────────────────────────────────────────────

class RepoExtractor:
    """
    Extrae y clona repositorios activos de una organización GitHub.

    Parameters
    ----------
    org : str
        Nombre de la organización en GitHub (ej. "encode").
    output_dir : str | Path
        Carpeta raíz donde se guardarán los repositorios clonados.
        Estructura generada:
            output_dir/
              <org>/
                <repo_name>/       ← clon del repositorio
                ...
              manifest.json        ← metadatos de todos los repos
    github_token : str, optional
        Token de acceso personal de GitHub.  Si se omite se usan
        las 60 req/h de la API pública.  Exportar como:
            export GITHUB_TOKEN=ghp_xxxx
    active_days : int
        Umbral en días para considerar un repo como "activo"
        (basado en pushed_at). Default: 30.
    max_repos : int
        Límite de repos a procesar (para estudios controlados). 0 = sin límite.
    clone : bool
        Si True clona los repos; si False solo descarga metadatos.
    depth : int
        Profundidad del clon (git clone --depth N). 1 = solo último commit.
    """

    GITHUB_API = "https://api.github.com"

    def __init__(
        self,
        org: str,
        output_dir: str | Path = "./repos",
        github_token: Optional[str] = None,
        active_days: int = 30,
        max_repos: int = 50,
        clone: bool = True,
        depth: int = 1,
    ) -> None:
        self.org = org
        self.output_dir = Path(output_dir)
        self.token = github_token or os.environ.get("GITHUB_TOKEN")
        self.active_days = active_days
        self.max_repos = max_repos
        self.clone = clone
        self.depth = depth

        self._headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "sbom-tool/1.0",
        }
        if self.token:
            self._headers["Authorization"] = f"Bearer {self.token}"

        self.repos: list[RepoInfo] = []

    # ── API helpers ──────────────────────────────────────────────────────────

    def _get(self, url: str, params: dict | None = None) -> list | dict:
        """GET paginado a la API de GitHub."""
        results = []
        while url:
            resp = requests.get(url, headers=self._headers, params=params, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                results.extend(data)
            else:
                return data
            # Paginación via Link header
            url = self._next_link(resp.headers.get("Link", ""))
            params = None  # ya está en la URL del link
        return results

    @staticmethod
    def _next_link(link_header: str) -> Optional[str]:
        """Extrae la URL 'next' del header Link de GitHub."""
        for part in link_header.split(","):
            if 'rel="next"' in part:
                return part.split(";")[0].strip().strip("<>")
        return None

    def _check_rate_limit(self) -> None:
        """Loguea el estado del rate limit actual."""
        try:
            data = self._get(f"{self.GITHUB_API}/rate_limit")
            core = data["resources"]["core"]
            logger.info(
                "Rate limit: %d/%d  —  reset en %s",
                core["remaining"], core["limit"],
                datetime.fromtimestamp(core["reset"]).strftime("%H:%M:%S"),
            )
        except Exception:
            pass

    # ── Listado de repos ─────────────────────────────────────────────────────

    def fetch_repo_list(self) -> list[RepoInfo]:
        """
        Consulta todos los repositorios públicos de la org y filtra por actividad.

        Returns
        -------
        list[RepoInfo]
            Repos activos ordenados por pushed_at descendente.
        """
        logger.info("Consultando repos de la org '%s'...", self.org)
        self._check_rate_limit()

        raw = self._get(
            f"{self.GITHUB_API}/orgs/{self.org}/repos",
            params={"type": "public", "per_page": 100, "sort": "pushed", "direction": "desc"},
        )
        logger.info("  Total repos públicos encontrados: %d", len(raw))

        all_repos = []
        for r in raw:
            info = RepoInfo(
                name=r["name"],
                full_name=r["full_name"],
                clone_url=r["clone_url"],
                html_url=r["html_url"],
                description=r.get("description") or "",
                language=r.get("language") or "Unknown",
                stars=r.get("stargazers_count", 0),
                forks=r.get("forks_count", 0),
                pushed_at=r["pushed_at"],
                default_branch=r.get("default_branch", "main"),
                size_kb=r.get("size", 0),
                topics=r.get("topics", []),
            )
            all_repos.append(info)

        # Filtrar activos
        active = [r for r in all_repos if r.is_active(self.active_days)]
        logger.info(
            "  Activos (último push ≤%d días): %d/%d",
            self.active_days, len(active), len(all_repos),
        )

        # Limitar cantidad
        if self.max_repos and len(active) > self.max_repos:
            logger.info("  Limitando a %d repos (--max-repos)", self.max_repos)
            active = active[: self.max_repos]

        self.repos = active
        return active

    # ── Clonado ──────────────────────────────────────────────────────────────

    def _clone_repo(self, repo: RepoInfo) -> bool:
        """
        Clona un repo en output_dir/<org>/<repo.name>/.
        Si ya existe hace git pull en vez de clonar.

        Returns True si exitoso.
        """
        dest = self.output_dir / self.org / repo.name
        repo.local_path = str(dest)

        if dest.exists() and (dest / ".git").exists():
            logger.info("    [pull]  %s", repo.name)
            cmd = ["git", "-C", str(dest), "pull", "--quiet"]
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            logger.info("    [clone] %s", repo.name)
            cmd = [
                "git", "clone",
                "--depth", str(self.depth),
                "--branch", repo.default_branch,
                "--quiet",
                repo.clone_url,
                str(dest),
            ]

        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=120)
            repo.clone_status = "ok"
            return True
        except subprocess.CalledProcessError as e:
            logger.warning("    ✗ Error clonando %s: %s", repo.name, e.stderr.decode())
            repo.clone_status = "failed"
            return False
        except subprocess.TimeoutExpired:
            logger.warning("    ✗ Timeout clonando %s", repo.name)
            repo.clone_status = "failed"
            return False

    def clone_repos(self) -> dict[str, int]:
        """
        Clona todos los repos en self.repos.

        Returns
        -------
        dict con contadores: ok, failed, skipped.
        """
        if not self.repos:
            logger.warning("No hay repos cargados. Llama fetch_repo_list() primero.")
            return {"ok": 0, "failed": 0, "skipped": 0}

        counters = {"ok": 0, "failed": 0, "skipped": 0}
        total = len(self.repos)

        logger.info("Clonando %d repositorios en '%s'...", total, self.output_dir)

        for i, repo in enumerate(self.repos, 1):
            logger.info("  [%d/%d] %s", i, total, repo.name)
            if not self.clone:
                repo.clone_status = "skipped"
                counters["skipped"] += 1
                continue
            ok = self._clone_repo(repo)
            counters["ok" if ok else "failed"] += 1

        return counters

    # ── Manifiesto ───────────────────────────────────────────────────────────

    def save_manifest(self) -> Path:
        """
        Guarda un JSON con metadatos de todos los repos procesados.

        Archivo: output_dir/<org>/manifest.json
        """
        manifest_path = self.output_dir / self.org / "manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)

        manifest = {
            "org": self.org,
            "extracted_at": datetime.utcnow().isoformat() + "Z",
            "active_days_threshold": self.active_days,
            "total_repos": len(self.repos),
            "repos": [asdict(r) for r in self.repos],
        }

        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
        logger.info("Manifiesto guardado: %s", manifest_path)
        return manifest_path

    # ── Flujo principal ──────────────────────────────────────────────────────

    def run(self) -> Path:
        """
        Ejecuta el flujo completo:
          1. fetch_repo_list()
          2. clone_repos()
          3. save_manifest()

        Returns
        -------
        Path al manifiesto generado.
        """
        self.fetch_repo_list()
        counters = self.clone_repos()

        logger.info(
            "Clonado completo → ok:%d  failed:%d  skipped:%d",
            counters["ok"], counters["failed"], counters["skipped"],
        )

        return self.save_manifest()


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="repo_extractor",
        description="Extrae y clona repositorios activos de una organización GitHub.",
    )
    p.add_argument("--org",        required=True,  help="Nombre de la organización GitHub")
    p.add_argument("--output",     default="./repos", help="Carpeta de salida (default: ./repos)")
    p.add_argument("--token",      default=None,   help="GitHub token (o usar GITHUB_TOKEN env)")
    p.add_argument("--days",       type=int, default=30, help="Ventana de actividad en días (default: 30)")
    p.add_argument("--max-repos",  type=int, default=50, help="Máximo de repos a procesar (default: 50)")
    p.add_argument("--no-clone",   action="store_true",  help="Solo descarga metadatos, no clona")
    p.add_argument("--depth",      type=int, default=1,  help="Profundidad del clon git (default: 1)")
    p.add_argument("--verbose",    action="store_true",  help="Logging detallado")
    return p


def main(argv: list[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    extractor = RepoExtractor(
        org=args.org,
        output_dir=args.output,
        github_token=args.token,
        active_days=args.days,
        max_repos=args.max_repos,
        clone=not args.no_clone,
        depth=args.depth,
    )

    manifest_path = extractor.run()
    print(f"\nExtracción completada. Manifiesto: {manifest_path}")


if __name__ == "__main__":
    main()
