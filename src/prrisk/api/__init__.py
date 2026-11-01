"""HTTP API.

POST /v1/review/diff    analyse a raw unified diff (line-level checks only)
POST /v1/review/github  analyse a GitHub pull request with full context
GET  /v1/health
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.concurrency import run_in_threadpool

from prrisk import __version__
from prrisk.engine import MAX_DIFF_BYTES, analyze
from prrisk.errors import DiffParseError, InputTooLargeError, PRRiskError, SourceError
from prrisk.github import GitHubClient
from prrisk.report import Report

log = logging.getLogger("prrisk.api")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PRRISK_", env_file=".env", extra="ignore")

    api_key_hashes: str = ""  # SHA-256 hex digests, comma separated
    github_token: str = ""

    def key_hashes(self) -> frozenset[str]:
        return frozenset(h.strip().lower() for h in self.api_key_hashes.split(",") if h.strip())


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


class DiffRequest(BaseModel):
    diff: str = Field(min_length=1, max_length=MAX_DIFF_BYTES)


class GitHubRequest(BaseModel):
    repo: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
    pr: int = Field(ge=1)
    comment: bool = False


class AuthError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        self.status, self.detail = status, detail


_STATUS = {DiffParseError: 422, InputTooLargeError: 413, SourceError: 502}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    hashes = settings.key_hashes()
    app = FastAPI(title="PR Risk Analyzer", version=__version__)

    def require_key(x_api_key: Annotated[str | None, Header()] = None) -> None:
        if not hashes:
            raise AuthError(503, "server has no API keys configured")
        if not x_api_key:
            raise AuthError(401, "missing X-API-Key header")
        digest = hashlib.sha256(x_api_key.encode()).hexdigest()
        if not any(hmac.compare_digest(digest, h) for h in hashes):
            raise AuthError(401, "invalid API key")

    @app.exception_handler(AuthError)
    async def _auth(_: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status, content={"error": "AuthError", "detail": exc.detail}
        )

    @app.exception_handler(PRRiskError)
    async def _domain(_: Request, exc: PRRiskError) -> JSONResponse:
        return JSONResponse(
            status_code=_STATUS.get(type(exc), 400),
            content={"error": type(exc).__name__, "detail": str(exc)},
        )

    @app.exception_handler(RequestValidationError)
    async def _invalid(_: Request, exc: RequestValidationError) -> JSONResponse:
        detail = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        return JSONResponse(status_code=422, content={"error": "ValidationError", "detail": detail})

    @app.exception_handler(Exception)
    async def _unexpected(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error")
        return JSONResponse(
            status_code=500, content={"error": "InternalError", "detail": "unexpected server error"}
        )

    @app.get("/v1/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post("/v1/review/diff", response_model=Report, dependencies=[Depends(require_key)])
    async def review_diff(body: DiffRequest) -> Report:
        return await run_in_threadpool(analyze, body.diff)

    @app.post("/v1/review/github", response_model=Report, dependencies=[Depends(require_key)])
    async def review_github(body: GitHubRequest) -> Report:
        def work() -> Report:
            gh = GitHubClient(body.repo, settings.github_token or None)
            pr = gh.pull(body.pr)
            report = analyze(gh.pull_diff(body.pr), gh, pr["base_sha"], pr["head_sha"])
            if body.comment:
                gh.upsert_comment(body.pr, report.to_markdown())
            return report

        return await run_in_threadpool(work)

    return app
