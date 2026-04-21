"""
Uso:
  # Analizador completo
  python main.py --org encode --output-root ./workspace

  # Solo extracción (sin análisis)
  python main.py --org encode --output-root ./workspace --only extract

  # Solo análisis (repos ya clonados)
  python main.py --org encode --output-root ./workspace --only analyze

  # Sin clonar (solo metadatos + análisis de código local)
  python main.py --org encode --output-root ./workspace --no-clone

Variables de entorno:
  GITHUB_TOKEN   Token de acceso personal de GitHub (recomendado)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

# Aseguramos que el directorio del script esté en el path
sys.path.insert(0, str(Path(__file__).parent))

from repo_extractor import RepoExtractor
from repo_analyzer  import RepoAnalyzer

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analizador-sbom",
        description="Analizador de SBOM + análisis de vulnerabilidades para una organización GitHub.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # ── Organización ──────────────────────────────────────────────────────
    p.add_argument(
        "--org", required=True,
        help="Nombre de la organización GitHub (ej. encode, pallets, django)",
    )

    # ── Rutas ─────────────────────────────────────────────────────────────
    p.add_argument(
        "--output-root", default="./workspace",
        help="Carpeta raíz del workspace",
    )

    # ── Control del analizador ──────────────────────────────────────────────
    p.add_argument(
        "--only", choices=["extract", "analyze"], default=None,
        help="Ejecutar solo un paso del analizador (extract | analyze)",
    )

    # ── Parámetros de extracción ──────────────────────────────────────────
    p.add_argument(
        "--token", default=None,
        help="GitHub token (o usar env GITHUB_TOKEN)",
    )
    p.add_argument(
        "--days", type=int, default=30,
        help="Ventana de actividad: repos con push en los últimos N días",
    )
    p.add_argument(
        "--max-repos", type=int, default=50,
        help="Máximo de repositorios a procesar",
    )
    p.add_argument(
        "--no-clone", action="store_true",
        help="No clonar repos; solo descarga metadatos (útil si ya tienes los repos)",
    )
    p.add_argument(
        "--depth", type=int, default=1,
        help="Profundidad del git clone (1 = solo último commit)",
    )

    # ── Parámetros de análisis ────────────────────────────────────────────
    p.add_argument(
        "--grype-timeout", type=int, default=120,
        help="Timeout en segundos para cada ejecución de Grype (default: 120)",
    )
    p.add_argument(
        "--diagnose", action="store_true",
        help="Verificar que Grype está instalado y su BD lista, luego salir",
    )

    # ── General ───────────────────────────────────────────────────────────
    p.add_argument(
        "--verbose", action="store_true",
        help="Logging detallado (DEBUG)",
    )

    return p


def run_analyzer(args: argparse.Namespace) -> None:
    root = Path(args.output_root)

    repos_dir  = root / "repos"   / args.org
    sboms_dir  = root / "sboms"   / args.org
    reports_dir= root / "reports" / args.org

    run_extract = args.only in (None, "extract")
    run_analyze = args.only in (None, "analyze")

    # ══════════════════════════════════════════════════════════════════════
    #  PASO 1 — EXTRACCIÓN
    # ══════════════════════════════════════════════════════════════════════
    if run_extract:
        logger.info("▶ PASO 1: Extracción de repositorios")
        logger.info("  Organización  : %s", args.org)
        logger.info("  Ventana activa: %d días", args.days)
        logger.info("  Máx. repos    : %d", args.max_repos)
        logger.info("  Clonar        : %s", not args.no_clone)

        extractor = RepoExtractor(
            org=args.org,
            output_dir=repos_dir.parent,
            github_token=args.token or os.environ.get("GITHUB_TOKEN"),
            active_days=args.days,
            max_repos=args.max_repos,
            clone=not args.no_clone,
            depth=args.depth,
        )
        manifest_path = extractor.run()
        logger.info("  Manifiesto: %s", manifest_path)

        if not extractor.repos:
            logger.warning("No se encontraron repos activos. Verifica --days y el token.")
            if args.only == "extract":
                return
    else:
        logger.info("▶ Paso 1 omitido (--only analyze)")

    # ══════════════════════════════════════════════════════════════════════
    #  PASO 2 — ANÁLISIS
    # ══════════════════════════════════════════════════════════════════════
    if run_analyze:
        if not repos_dir.exists():
            logger.error(
                "  La carpeta de repos no existe: %s\n"
                "  Ejecuta primero con --only extract (o sin --only).",
                repos_dir,
            )
            sys.exit(1)

        logger.info("▶ PASO 2: Análisis de repositorios")
        logger.info("  Repos dir   : %s", repos_dir)
        logger.info("  SBOMs dir   : %s", sboms_dir)
        logger.info("  Reports dir : %s", reports_dir)

        if getattr(args, 'diagnose', False):
            RepoAnalyzer(
                repos_dir=repos_dir,
                sboms_dir=sboms_dir,
                output_dir=reports_dir,
                grype_timeout=args.grype_timeout,
            ).diagnose()
            return

        analyzer = RepoAnalyzer(
            repos_dir=repos_dir,
            sboms_dir=sboms_dir,
            output_dir=reports_dir,
            grype_timeout=args.grype_timeout,
        )
        report_paths = analyzer.run()

        print("\nReportes generados:")
        for name, path in report_paths.items():
            print(f"   {name:<12}: {path}")
    else:
        logger.info("▶ Paso 2 omitido (--only extract)")

    print("\nAnalizador completado.")


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    run_analyzer(args)


if __name__ == "__main__":
    main()
