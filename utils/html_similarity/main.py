"""
main.py: HTML 유사도 분석 진입점

사용 예:
    # 모든 파일 분석 (기본)
    python main.py

    # HTML 디렉토리 직접 지정
    python main.py --html-dir ../html

    # 특정 그룹만 분석
    python main.py --groups youtube
    python main.py --groups youtube linkkf ohli

    # 여러 그룹 지정 시 그룹 간 교차 비교도 포함
    python main.py --groups youtube linkkf

    # 그룹 목록 확인
    python main.py --list-groups

    # 사용 가능한 방법 목록 확인
    python main.py --list
"""

import argparse
import re
import sys
from pathlib import Path

from utils.html_similarity.methods import get_all_methods, get_method, list_methods
from utils.html_similarity.pipeline import HTMLSimilarityPipeline
from utils.html_similarity.groups import SITE_GROUPS


def _domain(filename: str) -> str:
    m = re.match(r"^(.+?)_\d{6}", filename)
    return m.group(1) if m else filename


def filter_by_groups(html_dir: Path, group_names: list[str]) -> list[Path]:
    """지정된 그룹에 속한 파일만 반환.

    cross=False: 각 그룹 내 파일만
    cross=True : 지정된 모든 그룹의 파일 (그룹 간 교차 비교 포함)
    """
    # 그룹명 검증
    unknown = set(group_names) - set(SITE_GROUPS)
    if unknown:
        print(f"알 수 없는 그룹: {unknown}")
        print(f"사용 가능한 그룹: {list(SITE_GROUPS.keys())}")
        sys.exit(1)

    target_domains: set[str] = set()
    for g in group_names:
        target_domains.update(SITE_GROUPS[g])

    all_paths = sorted(
        p for p in html_dir.iterdir() if p.suffix.lower() in {".html", ".htm"}
    )
    filtered = [p for p in all_paths if _domain(p.name) in target_domains]

    if not filtered:
        print(f"그룹 {group_names}에 해당하는 HTML 파일이 없습니다.")
        print(f"대상 도메인: {target_domains}")
        sys.exit(1)

    return filtered


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="HTML 유사도 분석",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--html-dir", default="../html",
        help="HTML 파일 디렉토리 (기본: ../html)",
    )
    parser.add_argument(
        "--methods", nargs="+", default=None,
        help="사용할 방법 (기본: 전체). 예: --methods shape_content",
    )
    parser.add_argument(
        "--groups", nargs="+", default=None,
        metavar="GROUP",
        help="분석할 그룹 (기본: 전체). 예: --groups youtube  --groups youtube linkkf",
    )
    parser.add_argument(
        "--output-dir", default="output",
        help="결과 저장 루트 디렉토리 (기본: output/)",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="사용 가능한 방법 목록 출력 후 종료",
    )
    parser.add_argument(
        "--list-groups", action="store_true",
        help="정의된 그룹 목록 출력 후 종료",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.list:
        print("사용 가능한 방법:")
        for m in list_methods():
            print(f"  {m}")
        sys.exit(0)

    if args.list_groups:
        print("정의된 그룹:")
        for name, domains in SITE_GROUPS.items():
            print(f"  {name:12s}: {', '.join(domains)}")
        sys.exit(0)

    if args.methods:
        methods = [get_method(name) for name in args.methods]
    else:
        methods = get_all_methods()

    print("분석 방법:")
    for m in methods:
        print(f"  [{m.name}] {m.description}")

    html_dir = Path(args.html_dir)
    if args.groups:
        paths = filter_by_groups(html_dir, args.groups)
        print(f"\n그룹 필터: {args.groups}  ({len(paths)}개 파일)")
        for p in paths:
            print(f"  {p.name}")
    else:
        paths = None  # pipeline이 디렉토리 전체 사용

    pipeline = HTMLSimilarityPipeline(methods, args.output_dir)

    if paths is not None:
        results = pipeline.run_paths(paths)
    else:
        results = pipeline.run(html_dir)

    for method in methods:
        top = sorted(results, key=lambda r: r[method.name], reverse=True)[:5]
        print(f"\n[{method.name}] 상위 유사 쌍:")
        for r in top:
            print(f"  {r[method.name]:.4f}  |  {r['file_a']}  vs  {r['file_b']}")


if __name__ == "__main__":
    main()
