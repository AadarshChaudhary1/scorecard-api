import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, field_validator

app = FastAPI(
    title="Multi-Tenant OpenSSF Scorecard API",
    description="Multi-tenant OpenSSF Scorecard scanning service",
    version="1.0.0",
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKENS_PATH = os.path.join(BASE_DIR, "tokens.json")
FIXTURE_PATH = os.path.join(BASE_DIR, "fixtures", "scorecard_sample.json")

def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)

TOKENS_DB = load_json(TOKENS_PATH)

class Scanner:
    """Scanner abstraction backed by the supplied fixture."""
    def scan(self, repository_url: str) -> dict:
        return load_json(FIXTURE_PATH)

scanner = Scanner()
SCANS_STORE: Dict[str, Dict[str, Any]] = {}

SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

def derive_severity(score: int) -> str:
    if score <= 2:
        return "CRITICAL"
    if score <= 4:
        return "HIGH"
    if score <= 7:
        return "MEDIUM"
    return "LOW"

class ScanRequestModel(BaseModel):
    repository_url: str = Field(
        ...,
        description="HTTPS GitHub or GitLab repository URL",
        examples=["https://github.com/acme-corp/payment-gateway"],
    )

    @field_validator("repository_url")
    @classmethod
    def validate_repo_url(cls, value: str):
        pattern = (
            r"^https://"
            r"(github\.com|gitlab\.com)/"
            r"[\w.-]+/"
            r"[\w.-]+"
            r"/?$"
        )
        if not re.match(pattern, value):
            raise ValueError(
                "must be a valid https git URL from github.com or gitlab.com"
            )
        return value

class ScanResponseModel(BaseModel):
    scan_id: str
    tenant_id: str
    repository_url: str
    status: str
    aggregate_score: float
    created_at: str

class IssueModel(BaseModel):
    issue_id: str
    check_name: str
    score: int
    severity: str
    title: str
    description: str
    evidence: List[Any]
    remediation_hint: str

class IssuesResponseModel(BaseModel):
    scan_id: str
    issues: List[IssueModel]

class ErrorModel(BaseModel):
    code: str
    message: str
    details: Optional[List[Any]] = None

class ErrorResponseModel(BaseModel):
    error: ErrorModel

ERROR_RESPONSES = {
    401: {"model": ErrorResponseModel, "description": "Unauthorized"},
    403: {"model": ErrorResponseModel, "description": "Forbidden"},
    404: {"model": ErrorResponseModel, "description": "Not Found"},
    422: {"model": ErrorResponseModel, "description": "Validation Error"},
}

def error_response(code: str, message: str, details: Optional[List[Any]] = None):
    body = {"error": {"code": code, "message": message}}
    if details is not None:
        body["error"]["details"] = details
    return body

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    details = [
        {
            "loc": list(error.get("loc", [])),
            "msg": error.get("msg", ""),
            "type": error.get("type", ""),
        }
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=error_response(
            "VALIDATION_ERROR",
            "Request body or query parameters failed schema validation",
            details,
        ),
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    status_code = exc.status_code
    code_map = {
        status.HTTP_401_UNAUTHORIZED: "UNAUTHORIZED",
        status.HTTP_403_FORBIDDEN: "FORBIDDEN",
        status.HTTP_404_NOT_FOUND: "NOT_FOUND",
        status.HTTP_400_BAD_REQUEST: "BAD_REQUEST",
    }
    code = code_map.get(status_code, "HTTP_ERROR")
    return JSONResponse(
        status_code=status_code,
        content=error_response(code, str(exc.detail)),
        headers=(
            {"WWW-Authenticate": "Bearer"}
            if status_code == status.HTTP_401_UNAUTHORIZED
            else None
        ),
    )

security = HTTPBearer(auto_error=False)

def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    user_info = TOKENS_DB.get(credentials.credentials)
    if not user_info:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown or invalid token",
        )
    return user_info

@app.post(
    "/scans",
    response_model=ScanResponseModel,
    status_code=status.HTTP_201_CREATED,
    tags=["scans"],
    summary="Create Scan",
    responses={
        401: {"model": ErrorResponseModel, "description": "Missing or invalid bearer token"},
        403: {"model": ErrorResponseModel, "description": "User is not an administrator"},
        422: {"model": ErrorResponseModel, "description": "Request validation failed"},
    },
)
def create_scan(
    payload: ScanRequestModel,
    user: Dict[str, str] = Depends(get_current_user),
):
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only users with admin role can trigger a scan",
        )

    scan_id = f"scn_{uuid.uuid4().hex[:10]}"
    created_at = datetime.now(timezone.utc).isoformat()
    scorecard_result = scanner.scan(payload.repository_url)
    aggregate_score = float(scorecard_result.get("score", 0.0))

    issues = []
    for check in scorecard_result.get("checks", []):
        score = int(check.get("score", 0))
        severity = derive_severity(score)
        check_name = check.get("name", "").strip()
        slug = re.sub(r"[^a-z0-9]+", "-", check_name.lower()).strip("-")
        issue_id = f"iss-{slug}"
        documentation = check.get("documentation", {})

        issues.append({
            "issue_id": issue_id,
            "check_name": check_name,
            "score": score,
            "severity": severity,
            "title": check.get("reason", ""),
            "description": documentation.get("short", ""),
            "evidence": check.get("details", []),
            "remediation_hint": (
                f"Address findings for {check_name} "
                f"to raise score above current value of {score}."
            ),
        })

    scan_record = {
        "scan_id": scan_id,
        "tenant_id": user["tenant_id"],
        "repository_url": payload.repository_url,
        "status": "COMPLETED",
        "aggregate_score": aggregate_score,
        "created_at": created_at,
        "issues": issues,
    }
    SCANS_STORE[scan_id] = scan_record

    return {
        "scan_id": scan_id,
        "tenant_id": user["tenant_id"],
        "repository_url": payload.repository_url,
        "status": "COMPLETED",
        "aggregate_score": aggregate_score,
        "created_at": created_at,
    }

@app.get(
    "/scans/{scan_id}",
    response_model=ScanResponseModel,
    tags=["scans"],
    summary="Get Scan",
    responses={
        401: {"model": ErrorResponseModel, "description": "Missing or invalid bearer token"},
        404: {"model": ErrorResponseModel, "description": "Scan not found or belongs to another tenant"},
        422: {"model": ErrorResponseModel, "description": "Request validation failed"},
    },
)
def get_scan(
    scan_id: str,
    user: Dict[str, str] = Depends(get_current_user),
):
    scan = SCANS_STORE.get(scan_id)
    if not scan or scan["tenant_id"] != user["tenant_id"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    return {
        "scan_id": scan["scan_id"],
        "tenant_id": scan["tenant_id"],
        "repository_url": scan["repository_url"],
        "status": scan["status"],
        "aggregate_score": scan["aggregate_score"],
        "created_at": scan["created_at"],
    }

@app.get(
    "/scans/{scan_id}/issues",
    response_model=IssuesResponseModel,
    tags=["scans"],
    summary="List Issues",
    responses={
        401: {"model": ErrorResponseModel, "description": "Missing or invalid bearer token"},
        404: {"model": ErrorResponseModel, "description": "Scan not found or belongs to another tenant"},
        422: {"model": ErrorResponseModel, "description": "Invalid severity filter"},
    },
)
def list_issues(
    scan_id: str,
    min_severity: Optional[str] = Query(
        default=None,
        pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$",
        description="Inclusive minimum severity filter",
    ),
    user: Dict[str, str] = Depends(get_current_user),
):
    scan = SCANS_STORE.get(scan_id)
    if not scan or scan["tenant_id"] != user["tenant_id"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    issues = scan["issues"]
    if min_severity:
        minimum_rank = SEVERITY_RANK[min_severity]
        issues = [
            issue
            for issue in issues
            if SEVERITY_RANK[issue["severity"]] >= minimum_rank
        ]

    return {"scan_id": scan_id, "issues": issues}
