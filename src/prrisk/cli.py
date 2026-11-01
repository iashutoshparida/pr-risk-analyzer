"""Command line.

  prrisk review  --base origin/main --head HEAD [--repo .]    analyse a local branch
  prrisk github  --repo owner/name --pr 12 [--comment]        analyse a PR through the API
  prrisk serve                                                run the HTTP API

Exit codes: 0 ok, 1 risk at or above --fail-on, 2 bad input or source error.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from prrisk.engine import analyze
from prrisk.errors import PRRiskError
from prrisk.github import GitHubClient
from prrisk.llm import AnthropicProvider, LLMProvider, OpenAIProvider
from prrisk.report import Report
from prrisk.source import LocalGitSource

LEVELS = ["low", "medium", "high", "critical"]


def make_llm(choice: str) -> LLMProvider | None:
    if choice == "none":
        return None
    env = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}[choice]
    key = os.environ.get(env)
    if not key:
        raise PRRiskError(f"--llm {choice} needs {env} in the environment")
    return OpenAIProvider(key) if choice == "openai" else AnthropicProvider(key)


def _emit(report: Report, fmt: str, out: str | None) -> None:
    text = report.to_markdown() if fmt == "md" else report.model_dump_json(indent=2)
    if out:
        Path(out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text + ("" if text.endswith("\n") else "\n"))


def _gate(report: Report, fail_on: str | None) -> int:
    if fail_on and LEVELS.index(report.summary.risk_level) >= LEVELS.index(fail_on):
        print(f"risk {report.summary.risk_level} >= --fail-on {fail_on}", file=sys.stderr)
        return 1
    return 0


def _review(args: argparse.Namespace) -> int:
    source = LocalGitSource(Path(args.repo))
    report = analyze(
        source.diff(args.base, args.head), source, args.base, args.head, make_llm(args.llm)
    )
    _emit(report, args.format, args.out)
    return _gate(report, args.fail_on)


def _github(args: argparse.Namespace) -> int:
    gh = GitHubClient(args.repo, os.environ.get("GITHUB_TOKEN"))
    pr = gh.pull(args.pr)
    report = analyze(gh.pull_diff(args.pr), gh, pr["base_sha"], pr["head_sha"], make_llm(args.llm))
    _emit(report, args.format, args.out)
    if args.comment:
        print(f"PR comment {gh.upsert_comment(args.pr, report.to_markdown())}", file=sys.stderr)
    return _gate(report, args.fail_on)


def _comment(args: argparse.Namespace) -> int:
    gh = GitHubClient(args.repo, os.environ.get("GITHUB_TOKEN"))
    print(gh.upsert_comment(args.pr, Path(args.file).read_text(encoding="utf-8")))
    return 0


def _serve(args: argparse.Namespace) -> int:  # pragma: no cover - thin uvicorn wrapper
    import uvicorn

    from prrisk.api import create_app

    uvicorn.run(create_app(), host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prrisk", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--format", choices=["md", "json"], default="md")
        p.add_argument("--out")
        p.add_argument("--fail-on", choices=LEVELS)
        p.add_argument("--llm", choices=["none", "openai", "anthropic"], default="none")

    rv = sub.add_parser("review", help="analyse base...head in a local git repository")
    rv.add_argument("--repo", default=".")
    rv.add_argument("--base", required=True)
    rv.add_argument("--head", default="HEAD")
    common(rv)
    rv.set_defaults(func=_review)

    gh = sub.add_parser("github", help="analyse a pull request through the GitHub API")
    gh.add_argument("--repo", required=True, help="owner/name")
    gh.add_argument("--pr", type=int, required=True)
    gh.add_argument("--comment", action="store_true", help="post or update the PR comment")
    common(gh)
    gh.set_defaults(func=_github)

    cm = sub.add_parser("comment", help="post a saved Markdown report as the PR comment")
    cm.add_argument("--repo", required=True)
    cm.add_argument("--pr", type=int, required=True)
    cm.add_argument("--file", required=True)
    cm.set_defaults(func=_comment)

    sv = sub.add_parser("serve", help="run the HTTP API")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.set_defaults(func=_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        code: int = args.func(args)
    except PRRiskError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
