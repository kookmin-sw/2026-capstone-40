"""공통 트리 빌딩 유틸리티."""

from __future__ import annotations

_STRUCTURAL_TAGS = {
    "html", "body",
    "div", "section", "article", "aside", "main",
    "header", "footer", "nav",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "p", "ul", "ol", "li",
    "table", "thead", "tbody", "tfoot", "tr", "th", "td",
    "form", "input", "button", "select", "textarea", "label",
    "figure", "figcaption",
}


def build_children_map(soup) -> tuple[list, dict[int, list], list]:
    """soup에서 구조 노드의 부모-자식 맵을 빌드.

    Returns:
        (nodes, children_map, roots)
    """
    nodes = soup.find_all(list(_STRUCTURAL_TAGS))
    if not nodes:
        return [], {}, []

    node_ids = {id(n) for n in nodes}
    children_map: dict[int, list] = {id(n): [] for n in nodes}
    roots: list = []

    for node in nodes:
        parent = getattr(node, "parent", None)
        struct_parent = None
        while parent is not None:
            if (hasattr(parent, "name")
                    and parent.name in _STRUCTURAL_TAGS
                    and id(parent) in node_ids):
                struct_parent = parent
                break
            parent = getattr(parent, "parent", None)

        if struct_parent is not None:
            children_map[id(struct_parent)].append(node)
        else:
            roots.append(node)

    return nodes, children_map, roots
