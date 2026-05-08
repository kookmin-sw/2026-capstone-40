


"""
ShapeContentMethod: 태그 무관 서브트리 형태 매칭 + 텍스트·CSS 클래스 비교

알고리즘:
    1. 각 노드의 '형태 해시' 계산 — 태그명 무시, 분기 구조만 반영
    2. 두 페이지에서 형태 해시가 일치하는 서브트리 쌍 탐색
    3. 크기·텍스트 Jaccard 기반 그리디 매칭
    4. 매칭된 서브트리에서 텍스트 토큰 + CSS 클래스명 수집 → 통합 Jaccard

    score = Jaccard(text_tokens_a ∪ css_classes_a,
                    text_tokens_b ∪ css_classes_b)
    (매칭된 서브트리 범위 내에서만 집계)

CSS 클래스는 'cls:' 접두사로 텍스트 토큰과 구분.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict

from utils.html_similarity.methods.base import HTMLSimilarityMethod
from utils.html_similarity.methods._tree_utils import build_children_map
from utils.html_similarity.preprocessor import parse

MIN_SIZE = 3


class ShapeContentMethod(HTMLSimilarityMethod):

    def compute(self, html_a: str, html_b: str) -> float:
        soup_a = parse(html_a)
        soup_b = parse(html_b)

        info_a = _build_info(soup_a)
        info_b = _build_info(soup_b)

        if not info_a or not info_b:
            return 0.0

        matches = _greedy_match(info_a, info_b)
        if not matches:
            return 0.0

        pool_a: set[str] = set()
        pool_b: set[str] = set()
        for m in matches:
            pool_a.update(_tokenize(m["text_a"]))
            pool_a.update(m["classes_a"])
            pool_b.update(_tokenize(m["text_b"]))
            pool_b.update(m["classes_b"])

        if not pool_a and not pool_b:
            return 0.0
        return round(_jaccard(pool_a, pool_b), 4)

    @property
    def name(self) -> str:
        return "shape_content"

    @property
    def description(self) -> str:
        return "태그 무관 형태 매칭 서브트리 내 텍스트+CSS 클래스 통합 Jaccard"


# ------------------------------------------------------------------ #
# 트리 구성 및 형태 해시
# ------------------------------------------------------------------ #

def _build_info(soup) -> dict[int, dict]:
    _, children_map, roots = build_children_map(soup)
    info: dict[int, dict] = {}

    def _compute(node) -> None:
        kids = children_map[id(node)]
        for k in kids:
            _compute(k)

        child_shapes = sorted(info[id(k)]["shape"] for k in kids)
        shape = hashlib.md5(",".join(child_shapes).encode()).hexdigest()[:16]
        size  = 1 + sum(info[id(k)]["size"] for k in kids)

        info[id(node)] = {
            "node":     node,
            "shape":    shape,
            "size":     size,
            "children": [id(k) for k in kids],
        }

    for root in roots:
        _compute(root)

    return info


def _subtree_ids(nid: int, info: dict) -> set[int]:
    result = {nid}
    stack = list(info[nid]["children"])
    while stack:
        cur = stack.pop()
        result.add(cur)
        stack.extend(info[cur]["children"])
    return result


def _subtree_classes(nid: int, info: dict) -> set[str]:
    """서브트리 내 모든 CSS 클래스명 집합 (접두사 'cls:' 부착)."""
    classes = set()
    stack = [nid]
    while stack:
        cur = stack.pop()
        node = info[cur]["node"]
        for cls in (node.get("class") or []):
            if cls:
                classes.add("cls:" + cls.lower())
        stack.extend(info[cur]["children"])
    return classes


# ------------------------------------------------------------------ #
# 그리디 매칭
# ------------------------------------------------------------------ #

def _greedy_match(info_a: dict, info_b: dict) -> list[dict]:
    shapes_a: dict[str, list] = defaultdict(list)
    shapes_b: dict[str, list] = defaultdict(list)

    for nid, d in info_a.items():
        if d["size"] >= MIN_SIZE:
            shapes_a[d["shape"]].append(nid)
    for nid, d in info_b.items():
        if d["size"] >= MIN_SIZE:
            shapes_b[d["shape"]].append(nid)

    common = set(shapes_a) & set(shapes_b)

    candidates: list[tuple] = []
    for shape in sorted(common):        # sorted: set 반복 순서 비결정성 제거
        for nid_a in shapes_a[shape]:
            text_a  = info_a[nid_a]["node"].get_text(separator=" ", strip=True)
            words_a = _tokenize(text_a)
            sz_a    = info_a[nid_a]["size"]
            for nid_b in shapes_b[shape]:
                words_b = _tokenize(info_b[nid_b]["node"].get_text(separator=" ", strip=True))
                jac     = _jaccard(words_a, words_b)
                sz_b    = info_b[nid_b]["size"]
                candidates.append((jac, sz_a + sz_b, sz_a, sz_b, nid_a, nid_b))

    candidates.sort(reverse=True)       # stable sort: 삽입 순서 보존, id는 최후 tiebreaker

    covered_a: set[int] = set()
    covered_b: set[int] = set()
    matches: list[dict] = []

    for jac, _, sz_a, sz_b, nid_a, nid_b in candidates:
        if nid_a in covered_a or nid_b in covered_b:
            continue

        covered_a.update(_subtree_ids(nid_a, info_a))
        covered_b.update(_subtree_ids(nid_b, info_b))

        matches.append({
            "size_a":    sz_a,
            "size_b":    sz_b,
            "text_a":    info_a[nid_a]["node"].get_text(separator=" ", strip=True),
            "text_b":    info_b[nid_b]["node"].get_text(separator=" ", strip=True),
            "classes_a": _subtree_classes(nid_a, info_a),
            "classes_b": _subtree_classes(nid_b, info_b),
        })

    return matches


# ------------------------------------------------------------------ #
# 텍스트·유사도 유틸
# ------------------------------------------------------------------ #

def _tokenize(text: str) -> set[str]:
    return {w.lower() for w in text.split() if len(w) >= 2}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)
