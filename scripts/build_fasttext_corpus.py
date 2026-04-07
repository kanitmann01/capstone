from __future__ import annotations

import argparse

from app.service import AppService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a FastText corpus from a labeled CSV.")
    parser.add_argument("input_csv", help="Labeled CSV with url and is_phishing columns.")
    parser.add_argument(
        "--output",
        default=None,
        help="Output corpus path. Defaults to the configured FastText corpus path.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    service = AppService()
    result = service.export_fasttext_corpus_from_csv(args.input_csv, args.output or service.config.fasttext_corpus_path)
    print("FastText corpus generated")
    print(f"rows: {result['rows']}")
    print(f"corpus_path: {result['corpus_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
