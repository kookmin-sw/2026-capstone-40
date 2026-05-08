"""
ShapeContentRatioMethod: 임계값 이상의 서브트리 쌍 텍스트 Jaccard >= 임계값 포함

shape_content 방식 비교:
    shape_content       : 매칭 서브트리 전체 텍스트를 합산 후 하나의 Jaccard
    shape_content_ratio : 매칭 쌍별로 Jaccard 계산 후 임계값 이상 쌍만 포함

임계값 탐색 (analyze_jaccard_dist.py):
    threshold=0.10  SAME above=0.481  DIFF above=0.063  gap=0.418  (최대)
"""

from __future__ import annotations

from utils.html_similarity.methods.base import HTMLSimilarityMethod
from utils.html_similarity.methods.shape_content import _build_info, _greedy_match, _tokenize, _jaccard
from utils.html_similarity.preprocessor import parse

THRESHOLD = 0.1


class ShapeContentRatioMethod(HTMLSimilarityMethod):

    def compute(self, html_a: str, html_b: str) -> float:
        info_a = _build_info(parse(html_a))
        info_b = _build_info(parse(html_b))

        if not info_a or not info_b:
            return 0.0

        matches = _greedy_match(info_a, info_b)
        if not matches:
            return 0.0

        above = sum(
            1 for m in matches
            if _jaccard(_tokenize(m["text_a"]), _tokenize(m["text_b"])) >= THRESHOLD
        )

        return round(above / len(matches), 4)

    @property
    def name(self) -> str:
        return "shape_content_ratio"

    @property
    def description(self) -> str:
        return f"매칭 쌍별 텍스트 Jaccard >= {THRESHOLD} 쌍만 포함"
