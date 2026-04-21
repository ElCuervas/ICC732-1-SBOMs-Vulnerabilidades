"""
=========
Generación de SBOMs y análisis de vulnerabilidades.

Clases principales
------------------
RepoExtractor   — descarga repos activos de una org GitHub
SBOMGenerator   — genera un SBOM CycloneDX 1.4 JSON desde un repo local
RepoAnalyzer    — analiza carpetas de repos, genera SBOMs y detecta CVEs
"""

from .repo_extractor import RepoExtractor, RepoInfo
from .sbom_generator import SBOMGenerator, SBOMResult, Component
from .repo_analyzer  import RepoAnalyzer, RepoAnalysisResult, VulnerabilityFinding

__all__ = [
    "RepoExtractor", "RepoInfo",
    "SBOMGenerator", "SBOMResult", "Component",
    "RepoAnalyzer", "RepoAnalysisResult", "VulnerabilityFinding",
]
