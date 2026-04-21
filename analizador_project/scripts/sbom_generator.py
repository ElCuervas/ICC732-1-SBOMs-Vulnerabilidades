"""
Clase responsable de generar un SBOM en formato CycloneDX 1.4 (JSON)
a partir del contenido de un repositorio local.

Detecta automáticamente el ecosistema del repositorio:
  - Python  → requirements*.txt, Pipfile, pyproject.toml, setup.cfg, setup.py
  - Node.js → package.json / package-lock.json
  - Ruby    → Gemfile / Gemfile.lock
  - Java    → pom.xml, build.gradle
  - Go      → go.mod
  - Rust    → Cargo.toml / Cargo.lock
  - PHP     → composer.json

Para cada dependencia detectada construye un componente CycloneDX con
su PURL (package URL), versión, licencia (si disponible) y scope.

Uso standalone:
    python sbom_generator.py --repo ./repos/encode/httpx --output ./sboms
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import logging
import re
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  Dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Component:
    """Un componente (dependencia) en el SBOM."""
    name: str
    version: str = "*"
    ecosystem: str = "unknown"
    scope: str = "required"           # required | optional | excluded
    purl: str = ""
    license_name: str = ""
    description: str = ""
    source_file: str = ""             # archivo donde se detectó

    def __post_init__(self) -> None:
        if not self.purl and self.name:
            self.purl = self._build_purl()

    def _build_purl(self) -> str:
        eco_map = {
            "python": "pypi",
            "nodejs": "npm",
            "ruby":   "gem",
            "java":   "maven",
            "go":     "golang",
            "rust":   "cargo",
            "php":    "composer",
        }
        pkg_type = eco_map.get(self.ecosystem, self.ecosystem)
        ver_part = f"@{self.version}" if self.version and self.version != "*" else ""
        return f"pkg:{pkg_type}/{self.name.lower()}{ver_part}"

    def to_cyclonedx(self) -> dict:
        comp: dict = {
            "type":    "library",
            "name":    self.name,
            "version": self.version,
            "purl":    self.purl,
            "scope":   self.scope,
        }
        if self.license_name:
            comp["licenses"] = [{"license": {"name": self.license_name}}]
        if self.description:
            comp["description"] = self.description
        return comp


@dataclass
class SBOMResult:
    """Resultado completo de la generación de SBOM para un repo."""
    repo_name: str
    repo_path: str
    ecosystem: str
    components: list[Component] = field(default_factory=list)
    manifest_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_cyclonedx(self) -> dict:
        """Serializa el resultado completo como CycloneDX 1.4 JSON."""
        serial = hashlib.md5(
            f"{self.repo_name}{self.generated_at}".encode()
        ).hexdigest()

        main_component = {
            "type":    "application",
            "name":    self.repo_name,
            "version": "HEAD",
            "purl":    f"pkg:github//{self.repo_name}",
        }

        return {
            "bomFormat":    "CycloneDX",
            "specVersion":  "1.4",
            "serialNumber": f"urn:uuid:{serial}",
            "version":      1,
            "metadata": {
                "timestamp": self.generated_at,
                "tools": [{
                    "vendor":  "sbom-tool",
                    "name":    "SBOMGenerator",
                    "version": "1.0",
                }],
                "component": main_component,
                "properties": [
                    {"name": "ecosystem",       "value": self.ecosystem},
                    {"name": "manifest_files",  "value": ", ".join(self.manifest_files)},
                ],
            },
            "components": [c.to_cyclonedx() for c in self.components],
            "dependencies": [{
                "ref":       main_component["purl"],
                "dependsOn": [c.purl for c in self.components if c.scope == "required"],
            }],
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Parsers por ecosistema
# ─────────────────────────────────────────────────────────────────────────────

def _parse_requirements_txt(path: Path, scope: str = "required") -> list[Component]:
    """Parsea requirements*.txt (incluyendo constraints)."""
    components = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-r", "-c", "--")):
            continue
        # Separar nombre y versión: pkg==1.2.3, pkg>=1.0, pkg[extra]>=1.0
        m = re.match(r'^([A-Za-z0-9_\-\.]+)(?:\[.*?\])?([^;#]*)', line)
        if not m:
            continue
        name    = m.group(1).strip().lower().replace("_", "-")
        version = m.group(2).strip().lstrip("=><! ^~").split(",")[0].strip() or "*"
        components.append(Component(
            name=name, version=version, ecosystem="python",
            scope=scope, source_file=path.name,
        ))
    return components


def _parse_pyproject_toml(path: Path) -> list[Component]:
    """Parsea dependencias de pyproject.toml (PEP 518/621 y Poetry)."""
    components = []
    try:
        data = tomllib.loads(path.read_text(errors="replace"))
    except Exception as e:
        logger.warning("  Error parseando %s: %s", path, e)
        return []

    # PEP 621 — project.dependencies
    for dep in data.get("project", {}).get("dependencies", []):
        m = re.match(r'^([A-Za-z0-9_\-\.]+)', dep)
        if m:
            name = m.group(1).lower().replace("_", "-")
            ver_m = re.search(r'[><=!^~]+\s*([^\s,]+)', dep)
            version = ver_m.group(1) if ver_m else "*"
            components.append(Component(
                name=name, version=version, ecosystem="python",
                scope="required", source_file=path.name,
            ))

    # Poetry — tool.poetry.dependencies
    for name, spec in data.get("tool", {}).get("poetry", {}).get("dependencies", {}).items():
        if name.lower() in ("python",):
            continue
        if isinstance(spec, str):
            version = spec.lstrip("^~>=<! ") or "*"
        elif isinstance(spec, dict):
            version = str(spec.get("version", "*")).lstrip("^~>=<! ") or "*"
        else:
            version = "*"
        components.append(Component(
            name=name.lower().replace("_", "-"),
            version=version, ecosystem="python",
            scope="required", source_file=path.name,
        ))

    # Optional / dev deps (Poetry)
    for name, spec in data.get("tool", {}).get("poetry", {}).get("dev-dependencies", {}).items():
        version = (spec if isinstance(spec, str) else spec.get("version", "*")).lstrip("^~>=<! ") or "*"
        components.append(Component(
            name=name.lower().replace("_", "-"),
            version=version, ecosystem="python",
            scope="optional", source_file=path.name,
        ))

    return components


def _parse_setup_cfg(path: Path) -> list[Component]:
    """Parsea install_requires de setup.cfg."""
    components = []
    cfg = configparser.ConfigParser()
    try:
        cfg.read_string(path.read_text(errors="replace"))
    except Exception:
        return []

    raw = cfg.get("options", "install_requires", fallback="")
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r'^([A-Za-z0-9_\-\.]+)', line)
        if m:
            name = m.group(1).lower().replace("_", "-")
            ver_m = re.search(r'[><=!]+\s*([^\s,;]+)', line)
            version = ver_m.group(1) if ver_m else "*"
            components.append(Component(
                name=name, version=version, ecosystem="python",
                scope="required", source_file=path.name,
            ))
    return components


def _parse_package_json(path: Path) -> list[Component]:
    """Parsea package.json de Node.js."""
    components = []
    try:
        data = json.loads(path.read_text(errors="replace"))
    except Exception:
        return []

    for dep_dict, scope in [
        (data.get("dependencies", {}),    "required"),
        (data.get("peerDependencies", {}), "required"),
        (data.get("devDependencies", {}),  "optional"),
    ]:
        for name, ver in dep_dict.items():
            version = str(ver).lstrip("^~>=<! ") or "*"
            components.append(Component(
                name=name, version=version, ecosystem="nodejs",
                scope=scope, source_file=path.name,
            ))
    return components


def _parse_package_lock(path: Path) -> list[Component]:
    """Parsea package-lock.json para obtener versiones resueltas exactas."""
    components = []
    try:
        data = json.loads(path.read_text(errors="replace"))
    except Exception:
        return []

    packages = data.get("packages", data.get("dependencies", {}))
    for pkg_path, info in packages.items():
        if not pkg_path or pkg_path == "":
            continue
        name    = pkg_path.lstrip("node_modules/").split("node_modules/")[-1]
        version = info.get("version", "*")
        scope   = "optional" if info.get("dev") else "required"
        components.append(Component(
            name=name, version=version, ecosystem="nodejs",
            scope=scope, source_file=path.name,
        ))
    return components


def _parse_go_mod(path: Path) -> list[Component]:
    """Parsea go.mod."""
    components = []
    in_require = False
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if in_require or line.startswith("require "):
            dep_line = line.replace("require ", "").strip()
            parts = dep_line.split()
            if len(parts) >= 2:
                components.append(Component(
                    name=parts[0], version=parts[1].lstrip("v"),
                    ecosystem="go", scope="required", source_file=path.name,
                ))
    return components


def _parse_cargo_toml(path: Path) -> list[Component]:
    """Parsea Cargo.toml de Rust."""
    components = []
    try:
        data = tomllib.loads(path.read_text(errors="replace"))
    except Exception:
        return []

    for dep_section, scope in [
        ("dependencies",      "required"),
        ("dev-dependencies",  "optional"),
        ("build-dependencies","optional"),
    ]:
        for name, spec in data.get(dep_section, {}).items():
            if isinstance(spec, str):
                version = spec.lstrip("^~>=<! ") or "*"
            elif isinstance(spec, dict):
                version = str(spec.get("version", "*")).lstrip("^~>=<! ") or "*"
            else:
                version = "*"
            components.append(Component(
                name=name, version=version, ecosystem="rust",
                scope=scope, source_file=path.name,
            ))
    return components


def _parse_gemfile(path: Path) -> list[Component]:
    """Parsea Gemfile de Ruby."""
    components = []
    for line in path.read_text(errors="replace").splitlines():
        m = re.match(r"""gem\s+['"]([^'"]+)['"]\s*,?\s*(?:['"]([^'"]+)['"])?""", line.strip())
        if m:
            components.append(Component(
                name=m.group(1), version=m.group(2) or "*",
                ecosystem="ruby", scope="required", source_file=path.name,
            ))
    return components


def _parse_pom_xml(path: Path) -> list[Component]:
    """Parsea pom.xml de Maven (solo dependencias directas)."""
    import xml.etree.ElementTree as ET
    components = []
    try:
        tree = ET.parse(path)
        ns   = {"m": "http://maven.apache.org/POM/4.0.0"}
        for dep in tree.findall(".//m:dependency", ns):
            group   = dep.findtext("m:groupId",    namespaces=ns, default="")
            artifact= dep.findtext("m:artifactId", namespaces=ns, default="")
            version = dep.findtext("m:version",    namespaces=ns, default="*")
            scope   = dep.findtext("m:scope",      namespaces=ns, default="required")
            name    = f"{group}:{artifact}" if group else artifact
            components.append(Component(
                name=name, version=version, ecosystem="java",
                scope="optional" if scope in ("test","provided") else "required",
                source_file=path.name,
            ))
    except Exception as e:
        logger.warning("  Error parseando pom.xml: %s", e)
    return components


def _parse_composer_json(path: Path) -> list[Component]:
    """Parsea composer.json de PHP."""
    components = []
    try:
        data = json.loads(path.read_text(errors="replace"))
    except Exception:
        return []
    for dep_key, scope in [("require","required"),("require-dev","optional")]:
        for name, ver in data.get(dep_key, {}).items():
            if name == "php":
                continue
            version = str(ver).lstrip("^~>=<! ") or "*"
            components.append(Component(
                name=name, version=version, ecosystem="php",
                scope=scope, source_file=path.name,
            ))
    return components


# ─────────────────────────────────────────────────────────────────────────────
#  Clase principal
# ─────────────────────────────────────────────────────────────────────────────

class SBOMGenerator:
    """
    Genera un SBOM CycloneDX 1.4 (JSON) a partir de un repositorio local.

    Parameters
    ----------
    repo_path : str | Path
        Ruta al repositorio clonado localmente.
    output_dir : str | Path
        Carpeta donde se guardará el archivo .cyclonedx.json.
    deduplicate : bool
        Elimina componentes duplicados (mismo nombre+versión). Default: True.
    """

    # Archivos reconocidos por ecosistema, en orden de prioridad
    MANIFEST_PRIORITY: list[tuple[str, str]] = [
        # (glob_pattern, ecosystem)
        ("package-lock.json",   "nodejs"),
        ("package.json",        "nodejs"),
        ("pyproject.toml",      "python"),
        ("requirements.txt",    "python"),
        ("requirements-dev.txt","python"),
        ("requirements-test.txt","python"),
        ("requirements/*.txt",  "python"),
        ("setup.cfg",           "python"),
        ("Pipfile",             "python"),
        ("go.mod",              "go"),
        ("Cargo.toml",          "rust"),
        ("Gemfile",             "ruby"),
        ("pom.xml",             "java"),
        ("build.gradle",        "java"),
        ("composer.json",       "php"),
    ]

    def __init__(
        self,
        repo_path: str | Path,
        output_dir: str | Path = "./sboms",
        deduplicate: bool = True,
    ) -> None:
        self.repo_path   = Path(repo_path)
        self.output_dir  = Path(output_dir)
        self.deduplicate = deduplicate

        if not self.repo_path.exists():
            raise FileNotFoundError(f"Repositorio no encontrado: {self.repo_path}")

    # ── Detección de ecosistema ───────────────────────────────────────────────

    def _detect_manifests(self) -> list[tuple[Path, str]]:
        """
        Encuentra archivos de manifiesto en el repositorio.

        Returns list of (path, ecosystem).
        """
        found: list[tuple[Path, str]] = []
        for pattern, eco in self.MANIFEST_PRIORITY:
            for p in self.repo_path.glob(pattern):
                if p.is_file() and ".git" not in p.parts:
                    found.append((p, eco))
        return found

    @staticmethod
    def _dominant_ecosystem(manifests: list[tuple[Path, str]]) -> str:
        """Ecosistema con más archivos de manifiesto."""
        from collections import Counter
        if not manifests:
            return "unknown"
        return Counter(eco for _, eco in manifests).most_common(1)[0][0]

    # ── Parseo de componentes ─────────────────────────────────────────────────

    def _parse_manifest(self, path: Path, eco: str) -> list[Component]:
        """Despachador: elige el parser correcto para cada archivo."""
        dispatch = {
            "requirements.txt":     lambda p: _parse_requirements_txt(p),
            "requirements-dev.txt": lambda p: _parse_requirements_txt(p, "optional"),
            "requirements-test.txt":lambda p: _parse_requirements_txt(p, "optional"),
            "pyproject.toml":       _parse_pyproject_toml,
            "setup.cfg":            _parse_setup_cfg,
            "package.json":         _parse_package_json,
            "package-lock.json":    _parse_package_lock,
            "go.mod":               _parse_go_mod,
            "Cargo.toml":           _parse_cargo_toml,
            "Gemfile":              _parse_gemfile,
            "pom.xml":              _parse_pom_xml,
            "composer.json":        _parse_composer_json,
        }
        fn = dispatch.get(path.name)
        if fn:
            try:
                return fn(path)
            except Exception as e:
                logger.warning("  Error parseando %s: %s", path.name, e)
        elif eco == "python" and path.suffix == ".txt":
            return _parse_requirements_txt(path)
        return []

    @staticmethod
    def _dedup(components: list[Component]) -> list[Component]:
        """Elimina duplicados manteniendo el de mayor versión."""
        seen: dict[str, Component] = {}
        for comp in components:
            key = f"{comp.ecosystem}:{comp.name}"
            if key not in seen or comp.version > seen[key].version:
                seen[key] = comp
        return list(seen.values())

    # ── Flujo principal ───────────────────────────────────────────────────────

    def generate(self) -> SBOMResult:
        """
        Genera el SBOM para el repositorio configurado.

        Returns
        -------
        SBOMResult con la lista de componentes y el SBOM CycloneDX.
        """
        repo_name = self.repo_path.name
        logger.info("Generando SBOM para: %s", repo_name)

        manifests = self._detect_manifests()
        ecosystem = self._dominant_ecosystem(manifests)
        logger.info("  Ecosistema detectado : %s", ecosystem)
        logger.info("  Manifiestos encontrados: %d", len(manifests))

        all_components: list[Component] = []
        manifest_files: list[str] = []
        errors: list[str] = []

        for path, eco in manifests:
            rel = str(path.relative_to(self.repo_path))
            logger.info("  Parseando: %s", rel)
            manifest_files.append(rel)
            comps = self._parse_manifest(path, eco)
            logger.info("    → %d componentes", len(comps))
            all_components.extend(comps)

        if self.deduplicate:
            before = len(all_components)
            all_components = self._dedup(all_components)
            logger.info(
                "  Deduplicación: %d → %d componentes", before, len(all_components)
            )

        result = SBOMResult(
            repo_name=repo_name,
            repo_path=str(self.repo_path),
            ecosystem=ecosystem,
            components=all_components,
            manifest_files=manifest_files,
            errors=errors,
        )

        if not manifests:
            msg = f"No se encontraron archivos de manifiesto en {repo_name}"
            logger.warning("  ⚠️  %s", msg)
            result.errors.append(msg)

        return result

    def save(self, result: SBOMResult) -> Path:
        """
        Serializa el SBOMResult como CycloneDX 1.4 JSON y lo guarda en disco.

        Returns
        -------
        Path al archivo generado.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        out_path = self.output_dir / f"sbom_{result.repo_name}.cyclonedx.json"
        sbom_dict = result.to_cyclonedx()
        out_path.write_text(json.dumps(sbom_dict, indent=2, ensure_ascii=False))
        logger.info("  SBOM guardado: %s", out_path)
        return out_path

    def run(self) -> tuple[SBOMResult, Path]:
        """Genera y guarda el SBOM. Retorna (SBOMResult, ruta_del_archivo)."""
        result = self.generate()
        path   = self.save(result)
        return result, path


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sbom_generator",
        description="Genera un SBOM CycloneDX 1.4 JSON para un repositorio local.",
    )
    p.add_argument("--repo",    required=True, help="Ruta al repositorio local")
    p.add_argument("--output",  default="./sboms", help="Carpeta de salida (default: ./sboms)")
    p.add_argument("--no-dedup",action="store_true", help="No deduplicar componentes")
    p.add_argument("--verbose", action="store_true", help="Logging detallado")
    return p


def main(argv: list[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    gen    = SBOMGenerator(args.repo, args.output, deduplicate=not args.no_dedup)
    result, out_path = gen.run()

    print(f"\nSBOM generado")
    print(f"   Repositorio  : {result.repo_name}")
    print(f"   Ecosistema   : {result.ecosystem}")
    print(f"   Componentes  : {len(result.components)}")
    print(f"   Archivo      : {out_path}")


if __name__ == "__main__":
    main()
