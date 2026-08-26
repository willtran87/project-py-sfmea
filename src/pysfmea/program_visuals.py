"""Bounded visual projections for system assurance program reports."""

from __future__ import annotations

from html import escape
from typing import Any


def program_topology_svg(result: dict[str, Any]) -> str:
    """Render the bounded repository relationship topology as accessible SVG."""

    summary = result.get("summary", {})
    repositories = [str(value) for value in summary.get("repository_ids", [])][:40]
    positions = {
        repository_id: (45 + (index % 4) * 260, 45 + (index // 4) * 110)
        for index, repository_id in enumerate(repositories)
    }
    height = max(150, 95 + ((len(repositories) + 3) // 4) * 110)
    edges: list[tuple[str, str, str, str]] = []
    seen_edges: set[tuple[str, str, str]] = set()
    for relationship in result.get("relationships", []):
        source = str(relationship.get("source_repository", ""))
        target = str(relationship.get("target_repository", ""))
        kind = str(relationship.get("kind", ""))
        key = (source, target, kind)
        if source in positions and target in positions and key not in seen_edges:
            seen_edges.add(key)
            edges.append((source, target, kind, str(relationship.get("id", ""))))
        if len(edges) >= 100:
            break

    def svg_text(value: Any) -> str:
        return escape(str(value), quote=True)

    edge_svg = "".join(
        (
            f'<line x1="{positions[source][0] + 100}" y1="{positions[source][1] + 28}" '
            f'x2="{positions[target][0] + 100}" y2="{positions[target][1] + 28}" '
            'marker-end="url(#arrow)" class="edge">'
            f"<title>{svg_text(identifier)}: {svg_text(source)} {svg_text(kind)} "
            f"{svg_text(target)}</title></line>"
        )
        for source, target, kind, identifier in edges
    )
    node_svg = "".join(
        (
            f'<g class="node"><rect x="{x}" y="{y}" width="200" height="56" rx="9" />'
            f"<title>{svg_text(repository_id)}</title>"
            f'<text x="{x + 100}" y="{y + 34}" text-anchor="middle">'
            f"{svg_text(repository_id[:28] + ('…' if len(repository_id) > 28 else ''))}"
            "</text></g>"
        )
        for repository_id, (x, y) in positions.items()
    )
    if not repositories:
        node_svg = (
            '<text x="35" y="70" class="empty-svg">'
            "No bound repositories to visualize.</text>"
        )
    truncated = len(summary.get("repository_ids", [])) > len(repositories) or len(
        seen_edges
    ) >= 100
    note = (
        '<p class="diagram-note">The visual is bounded to 40 repositories and 100 '
        "unique repository-level edges; use the relationship table for the complete "
        "contract.</p>"
        if truncated
        else ""
    )
    return (
        f'<div class="topology" tabindex="0"><svg viewBox="0 0 1080 {height}" '
        'role="img" aria-labelledby="topology-title topology-description">'
        '<title id="topology-title">System assurance repository topology</title>'
        '<desc id="topology-description">Directed repository-level relationships derived '
        "from the verified assurance program.</desc>"
        '<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" '
        'orient="auto" markerUnits="strokeWidth"><path d="M0,0 L0,6 L8,3 z" />'
        f"</marker></defs>{edge_svg}{node_svg}</svg></div>{note}"
    )
