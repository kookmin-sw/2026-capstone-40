"""
HTMLSimilarityPipeline: 전체 분석 파이프라인

- HTML 디렉토리 로드
- 등록된 방법(들) 으로 모든 쌍 유사도 계산
- output/output_{timestamp}/results.xlsx 저장
"""

from __future__ import annotations

import time
from datetime import datetime
from itertools import combinations
from pathlib import Path
from typing import TYPE_CHECKING

from utils.html_similarity.preprocessor import load
import utils.html_similarity.excel_writer as excel_writer
from utils.html_similarity.groups import SITE_GROUPS

if TYPE_CHECKING:
    from utils.html_similarity.methods.base import HTMLSimilarityMethod

_SUPPORTED_EXT = {".html", ".htm"}


class HTMLSimilarityPipeline:

    def __init__(
        self,
        methods: list["HTMLSimilarityMethod"],
        output_base: str | Path = "output",
    ):
        self.methods = methods
        ts = datetime.now().strftime("%y%m%d_%H%M")
        self.run_dir = Path(output_base) / f"result_html_similarity_{ts}"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        print(f"결과 저장 폴더: {self.run_dir}")

    def run(self, html_dir: str | Path) -> list[dict]:
        """디렉토리 내 HTML 파일 전체 쌍 분석 후 Excel 저장."""
        html_dir = Path(html_dir)
        paths = sorted(p for p in html_dir.iterdir() if p.suffix.lower() in _SUPPORTED_EXT)
        return self.run_paths(paths)

    def run_paths(self, paths: list[Path]) -> list[dict]:
        """지정된 파일 목록으로 쌍 분석 후 Excel 저장."""
        paths = sorted(paths)

        if len(paths) < 2:
            raise ValueError(f"HTML 파일이 2개 이상 필요합니다. 현재: {len(paths)}개")

        print(f"\nHTML 로딩 중... ({len(paths)}개)")
        html_cache: dict[str, str] = {p.name: load(str(p)) for p in paths}

        pairs = list(combinations([p.name for p in paths], 2))
        total = len(pairs)
        print(f"\n[분석 시작] {len(paths)}개 파일 → {total}쌍 × {len(self.methods)}가지 방법\n")

        results: list[dict] = []
        for i, (name_a, name_b) in enumerate(pairs, 1):
            row: dict = {"file_a": name_a, "file_b": name_b}
            scores_str = []

            for method in self.methods:
                t0 = time.perf_counter()
                score = method.compute(html_cache[name_a], html_cache[name_b])
                elapsed = time.perf_counter() - t0
                row[method.name] = score
                scores_str.append(f"{method.name}={score:.4f} ({elapsed:.1f}s)")

            results.append(row)
            print(f"  ({i:3d}/{total}) {name_a}  vs  {name_b}")
            print(f"          {' | '.join(scores_str)}")

        method_names = [m.name for m in self.methods]
        excel_path = self.run_dir / "results.xlsx"
        excel_writer.save(results, method_names, excel_path, site_groups=SITE_GROUPS)

        print(f"\n완료: {total}쌍 분석")
        print(f"  Excel: {excel_path}")
        return results
