"""
TEDMethod: Tree Edit Distance 기반 HTML 유사도

score = 1 - ted(A, B) / (size_A + size_B)

태그명을 노드 레이블로 사용.
삽입/삭제/치환 비용 모두 1.
"""

from __future__ import annotations

import zss
from utils.html_similarity.methods.base import HTMLSimilarityMethod
from utils.html_similarity.preprocessor import parse

MIN_TAGS = {"html", "head", "[document]", "script", "style", "meta", "link", "noscript"}


def _to_zss(node) -> zss.Node | None:
    if not hasattr(node, "name") or node.name is None:
        return None
    if node.name in MIN_TAGS:
        return None

    znode = zss.Node(node.name)
    for child in getattr(node, "children", []):
        child_node = _to_zss(child)
        if child_node is not None:
            znode.addkid(child_node)
    return znode


def _tree_size(znode: zss.Node) -> int:
    return 1 + sum(_tree_size(c) for c in znode.children)


class TEDMethod(HTMLSimilarityMethod):

    def compute(self, html_a: str, html_b: str) -> float:
        soup_a = parse(html_a)
        soup_b = parse(html_b)

        root_a = _to_zss(soup_a.find("body") or soup_a)
        root_b = _to_zss(soup_b.find("body") or soup_b)

        if root_a is None or root_b is None:
            return 0.0

        sa = _tree_size(root_a)
        sb = _tree_size(root_b)
        denom = sa + sb
        if denom == 0:
            return 1.0

        dist = zss.simple_distance(root_a, root_b)
        return round(max(0.0, 1.0 - dist / denom), 4)

    @property
    def name(self) -> str:
        return "ted"

    @property
    def description(self) -> str:
        return "Tree Edit Distance 기반 유사도 (1 - ted / (|A|+|B|))"
