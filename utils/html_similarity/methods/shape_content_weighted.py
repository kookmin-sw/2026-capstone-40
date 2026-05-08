"""
ShapeContentWeightedMethod: 두 커버리지 및 품질 지표 가중 합산

score = W_S1 * s1 + W_S2 * s2

    s1 = shape-type Jaccard
         |{shape 집합 in A} ∩ {shape 집합 in B}| / |... ∪ ...|
         (태그 무관 구조 해시 기반 교집합)

    s2 = quality ratio
         텍스트 Jaccard >= THRESHOLD 인 매칭 쌍 / 전체 매칭 쌍 수

최적 파라미터 (optimize_weights.py, AUC=0.9860):
    W_S1=0.85  W_S2=0.15  THRESHOLD=0.15
"""

from __future__ import annotations

from utils.html_similarity.methods.base import HTMLSimilarityMethod
from utils.html_similarity.methods.shape_content import _build_info, _greedy_match, _tokenize, _jaccard, MIN_SIZE
from utils.html_similarity.preprocessor import parse

W_S1 = 0.85
W_S2 = 0.15
THRESHOLD = 0.15


class ShapeContentWeightedMethod(HTMLSimilarityMethod):

    def compute(self, html_a: str, html_b: str) -> float:
        info_a = _build_info(parse(html_a))
        info_b = _build_info(parse(html_b))

        if not info_a or not info_b:
            return 0.0

        types_a = {d["shape"] for d in info_a.values() if d["size"] >= MIN_SIZE}
        types_b = {d["shape"] for d in info_b.values() if d["size"] >= MIN_SIZE}

        union = len(types_a | types_b)
        s1 = len(types_a & types_b) / union if union > 0 else 0.0

        matches = _greedy_match(info_a, info_b)
        if not matches:
            s2 = 0.0
        else:
            above = sum(
                1 for m in matches
                if _jaccard(_tokenize(m["text_a"]), _tokenize(m["text_b"])) >= THRESHOLD
            )
            s2 = above / len(matches)

        return round(W_S1 * s1 + W_S2 * s2, 4)

    @property
    def name(self) -> str:
        return "shape_content_weighted"

    @property
    def description(self) -> str:
        return f"shape-type Jaccard × {W_S1} + quality_ratio(thr={THRESHOLD}) × {W_S2}  [AUC=0.9860]"
