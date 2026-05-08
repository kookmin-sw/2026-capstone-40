"""
PQGramMethod: pq-gram 기반 트리 유사도

Augsten et al. (2005) 알고리즘.
각 노드에 대해 (p개 조상 레이블 + q개 자식 윈도우) 튜플을 생성하여
멀티셋으로 수집한 뒤 Dice 계수로 비교한다.

  pq-gram similarity = 2|P_A ∩ P_B| / (|P_A| + |P_B|)

기본값 p=2, q=2:
    gram 예) (body, table, *, tbody) — 조상 2개 + 자식 윈도우 2개
    부모 context + 자식 context 를 동시에 포착 → subtree_hash 보다 로컬 구조에 민감

subtree_hash 와의 차이:
    subtree_hash : 전체 서브트리 재귀 해시 → 전역 구조 패턴 비교
    pq_gram      : 각 노드 주변 (p+q)-튜플 → 로컬 맥락 비교, 빈도 반영
"""

from __future__ import annotations

from collections import Counter

from utils.html_similarity.methods.base import HTMLSimilarityMethod
from utils.html_similarity.methods._tree_utils import build_children_map
from utils.html_similarity.preprocessor import parse

_DUMMY = "*"


class PQGramMethod(HTMLSimilarityMethod):

    def __init__(self, p: int = 2, q: int = 2):
        self.p = p
        self.q = q

    def compute(self, html_a: str, html_b: str) -> float:
        grams_a = _extract_pqgrams(parse(html_a), self.p, self.q)
        grams_b = _extract_pqgrams(parse(html_b), self.p, self.q)
        return round(_dice(grams_a, grams_b), 4)

    @property
    def name(self) -> str:
        return "pq_gram"

    @property
    def description(self) -> str:
        return f"pq-gram 트리 유사도 Dice (p={self.p}, q={self.q})"


def _extract_pqgrams(soup, p: int, q: int) -> Counter:
    _, children_map, roots = build_children_map(soup)
    grams: Counter = Counter()
    root_ancestors = (_DUMMY,) * (p - 1)
    for root in roots:
        _collect(root, root_ancestors, children_map, p, q, grams)
    return grams


def _collect(node, ancestors: tuple, children_map: dict, p: int, q: int, grams: Counter) -> None:
    anc = (ancestors + (node.name,))[-p:]
    kids = children_map[id(node)]

    child_labels = (
        [_DUMMY] * (q - 1)
        + [c.name for c in kids]
        + [_DUMMY] * (q - 1)
    )

    for i in range(len(child_labels) - q + 1):
        grams[anc + tuple(child_labels[i:i + q])] += 1

    for child in kids:
        _collect(child, anc, children_map, p, q, grams)


def _dice(a: Counter, b: Counter) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = sum(min(a[k], b[k]) for k in set(a) & set(b))
    return 2 * inter / (sum(a.values()) + sum(b.values()))
