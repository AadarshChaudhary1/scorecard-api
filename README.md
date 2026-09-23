# Multi-Tenant OpenSSF Scorecard API

A small, synchronous **FastAPI** service that exposes OpenSSF Scorecard
results through a multi-tenant REST API.

The implementation is intentionally fixture-backed: it reads the
supplied `scorecard_sample.json` instead of executing the real OpenSSF
Scorecard CLI, exactly as required by the assignment.

## Highlights

-   Static Bearer-token authentication
-   Role-based authorization (`admin` / `viewer`)
-   Strict tenant isolation
-   Synchronous scan processing
-   Fixture-backed scanner abstraction
-   Deterministic Scorecard severity mapping
-   Inclusive `min_severity` filtering
-   Normalized security-issue responses
-   Uniform structured error responses
-   OpenAPI 3.0.3 contract
-   In-memory storage with a deliberately small implementation footprint

------------------------------------------------------------------------

## 1. API Overview

The service exposes the three required endpoints:

  ---------------------------------------------------------------------------------
  Method            Endpoint                    Purpose           Access
  ----------------- --------------------------- ----------------- -----------------
  `POST`            `/scans`                    Create a scan     Admin only

  `GET`             `/scans/{scan_id}`          Read scan         Admin / Viewer
                                                metadata          

  `GET`             `/scans/{scan_id}/issues`   Read normalized   Admin / Viewer
                                                issues            
  ---------------------------------------------------------------------------------

All requests use:

``` text
Authorization: Bearer <token>
```

Interactive API documentation is available at:

``` text
http://localhost:8000/docs
```

OpenAPI JSON is available at:

``` text
http://localhost:8000/openapi.json
```

------------------------------------------------------------------------

## 2. Project Structure

``` text
scorecard-api/
├── app/
│   ├── __init__.py
│   └── main.py
├── fixtures/
│   └── scorecard_sample.json
├── .gitignore
├── README.md
├── SPEC.md
├── openapi.yaml
├── requirements.txt
└── tokens.json
```

### File responsibilities

-   `app/main.py` --- FastAPI application, authentication,
    authorization, validation, scan processing, normalization,
    filtering, and error handling.
-   `fixtures/scorecard_sample.json` --- supplied Scorecard result used
    by the fixture-backed scanner.
-   `tokens.json` --- static users, roles, and tenant assignments.
-   `SPEC.md` --- implementation specification covering authorization,
    normalization, and non-goals.
-   `openapi.yaml` --- standalone HTTP API contract.
-   `requirements.txt` --- Python dependencies.
-   `README.md` --- setup, API usage, verification, and limitations.

------------------------------------------------------------------------

## 3. Requirements

-   Python 3.10+
-   `pip`

The service uses:

-   FastAPI
-   Uvicorn
-   Pydantic

Install the pinned dependency ranges from `requirements.txt`.

------------------------------------------------------------------------

## 4. Run Locally

From the repository root:

### Windows PowerShell

``` powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### macOS / Linux

``` bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The server starts on:

``` text
http://localhost:8000
```

Swagger UI:

``` text
http://localhost:8000/docs
```

------------------------------------------------------------------------

## 5. Authentication and Tenancy

The exercise uses static bearer tokens. No JWT, login flow, user
database, or token signing is implemented.

  Token               User          Tenant         Role
  ------------------- ------------- -------------- ----------
  `tok_alice_admin`   `usr_alice`   `ten_acme`     `admin`
  `tok_bob_viewer`    `usr_bob`     `ten_acme`     `viewer`
  `tok_carol_admin`   `usr_carol`   `ten_globex`   `admin`

Authorization rules:

-   `admin` can create scans.
-   `admin` and `viewer` can read scans.
-   Every scan is associated with the tenant of the creating user.
-   Cross-tenant reads return `404 NOT_FOUND`.
-   Missing or invalid credentials return `401 UNAUTHORIZED`.
-   An authenticated viewer attempting to create a scan returns
    `403 FORBIDDEN`.

Returning `404` for a cross-tenant resource intentionally avoids
revealing whether that resource exists.

------------------------------------------------------------------------

# 6. Create a Scan

### Request

``` http
POST /scans
```

Only administrators may create scans.

``` bash
curl -X POST "http://localhost:8000/scans" \
  -H "Authorization: Bearer tok_alice_admin" \
  -H "Content-Type: application/json" \
  -d '{
    "repository_url": "https://github.com/acme-corp/payment-gateway"
  }'
```

### Successful response

``` json
{
  "scan_id": "scn_980849329c",
  "tenant_id": "ten_acme",
  "repository_url": "https://github.com/acme-corp/payment-gateway",
  "status": "COMPLETED",
  "aggregate_score": 3.4,
  "created_at": "2026-09-22T13:37:58.854899+00:00"
}
```

### Processing model

Scanning is synchronous:

``` text
POST /scans
     |
     v
Validate request
     |
     v
Authenticate + authorize
     |
     v
Read Scorecard fixture
     |
     v
Normalize checks
     |
     v
Store scan in memory
     |
     v
Return COMPLETED
```

There is intentionally no `PENDING` state or background job.

------------------------------------------------------------------------

# 7. Get Scan Metadata

### Request

``` http
GET /scans/{scan_id}
```

Both administrators and viewers can read scans belonging to their
tenant.

``` bash
curl "http://localhost:8000/scans/SCN_ID" \
  -H "Authorization: Bearer tok_bob_viewer"
```

Example response:

``` json
{
  "scan_id": "scn_980849329c",
  "tenant_id": "ten_acme",
  "repository_url": "https://github.com/acme-corp/payment-gateway",
  "status": "COMPLETED",
  "aggregate_score": 3.4,
  "created_at": "2026-09-22T13:37:58.854899+00:00"
}
```

Replace `SCN_ID` with the `scan_id` returned by `POST /scans`.

------------------------------------------------------------------------

# 8. List Scan Issues

### Request

``` http
GET /scans/{scan_id}/issues
```

``` bash
curl "http://localhost:8000/scans/SCN_ID/issues" \
  -H "Authorization: Bearer tok_bob_viewer"
```

The response contains normalized issues such as:

``` json
{
  "scan_id": "scn_980849329c",
  "issues": [
    {
      "issue_id": "iss-branch-protection",
      "check_name": "Branch-Protection",
      "score": 0,
      "severity": "CRITICAL",
      "title": "branch protection not enabled on development/release branches",
      "description": "Determines if the default and release branches are protected with GitHub's branch protection settings.",
      "evidence": [],
      "remediation_hint": "Address findings for Branch-Protection to raise score above current value of 0."
    }
  ]
}
```

------------------------------------------------------------------------

# 9. Severity Mapping and Filtering

Each Scorecard check has a score from `0` to `10`. The API derives
severity using this deterministic mapping:

     Score Severity
  -------- ------------
     `0–2` `CRITICAL`
     `3–4` `HIGH`
     `5–7` `MEDIUM`
    `8–10` `LOW`

Severity ordering is:

``` text
LOW < MEDIUM < HIGH < CRITICAL
```

The `min_severity` query parameter is inclusive.

For example:

``` bash
curl "http://localhost:8000/scans/SCN_ID/issues?min_severity=HIGH" \
  -H "Authorization: Bearer tok_bob_viewer"
```

returns both:

``` text
HIGH
CRITICAL
```

Supported values are:

``` text
LOW
MEDIUM
HIGH
CRITICAL
```

An invalid value is rejected with `422 VALIDATION_ERROR`.

------------------------------------------------------------------------

# 10. Normalization

Every Scorecard check is converted into one normalized security issue.

The API exposes:

``` text
issue_id
check_name
score
severity
title
description
evidence
remediation_hint
```

Normalization rules are defined in `SPEC.md`.

For the current fixture:

-   `title` comes from the Scorecard check's `reason`.
-   `description` comes from `documentation.short`.
-   `evidence` contains the raw `details` array.
-   `severity` is derived from the check score.
-   `issue_id` is generated deterministically from the check name.

Example:

``` text
Branch-Protection
       ↓
branch-protection
       ↓
iss-branch-protection
```

------------------------------------------------------------------------

# 11. Scanner Abstraction

The real OpenSSF Scorecard CLI is **not** executed.

Instead, the fixture is accessed through a small scanner abstraction:

``` python
class Scanner:
    def scan(self, repository_url: str) -> dict:
        ...
```

The current implementation reads:

``` text
fixtures/scorecard_sample.json
```

The repository URL is validated and stored with the scan, but the
fixture is the scan source.

This keeps the API independent from the scanning implementation and
allows a future real Scorecard adapter to replace the fixture reader
without changing the API layer.

------------------------------------------------------------------------

# 12. Error Contract

All API errors use the same structured envelope:

``` json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable message",
    "details": []
  }
}
```

`details` is included when validation information is available.

### Error status codes

  ------------------------------------------------------------------------
                          HTTP Code                  Meaning
  ---------------------------- --------------------- ---------------------
                         `401` `UNAUTHORIZED`        Missing or invalid
                                                     bearer token

                         `403` `FORBIDDEN`           Authenticated user
                                                     lacks permission

                         `404` `NOT_FOUND`           Resource does not
                                                     exist or belongs to
                                                     another tenant

                         `422` `VALIDATION_ERROR`    Request body or query
                                                     parameter is invalid
  ------------------------------------------------------------------------

### Invalid token

``` bash
curl "http://localhost:8000/scans/SCN_ID" \
  -H "Authorization: Bearer invalid_token"
```

Expected:

``` http
401 Unauthorized
```

### Viewer attempts to create a scan

``` bash
curl -X POST "http://localhost:8000/scans" \
  -H "Authorization: Bearer tok_bob_viewer" \
  -H "Content-Type: application/json" \
  -d '{
    "repository_url": "https://github.com/acme-corp/payment-gateway"
  }'
```

Expected:

``` http
403 Forbidden
```

``` json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "Only users with admin role can trigger a scan"
  }
}
```

### Invalid repository URL

``` bash
curl -X POST "http://localhost:8000/scans" \
  -H "Authorization: Bearer tok_alice_admin" \
  -H "Content-Type: application/json" \
  -d '{
    "repository_url": "not-a-valid-repository"
  }'
```

Expected:

``` http
422 Unprocessable Entity
```

------------------------------------------------------------------------

# 13. Tenant Isolation Verification

Create a scan using Alice:

``` bash
curl -X POST "http://localhost:8000/scans" \
  -H "Authorization: Bearer tok_alice_admin" \
  -H "Content-Type: application/json" \
  -d '{
    "repository_url": "https://github.com/acme-corp/payment-gateway"
  }'
```

Copy the returned `scan_id`.

Then attempt to access it using Carol:

``` bash
curl "http://localhost:8000/scans/SCN_ID" \
  -H "Authorization: Bearer tok_carol_admin"
```

Expected:

``` http
404 Not Found
```

The same tenant check is applied to:

``` text
GET /scans/{scan_id}/issues
```

------------------------------------------------------------------------

# 14. Verification Checklist

The implementation was checked against the assignment requirements and
fixture.

  Requirement                     Status
  ------------------------------- -------------
  `POST /scans`                   Implemented
  `GET /scans/{scan_id}`          Implemented
  `GET /scans/{scan_id}/issues`   Implemented
  Static bearer authentication    Implemented
  Admin-only scan creation        Implemented
  Viewer/admin reads              Implemented
  Tenant isolation                Implemented
  Cross-tenant `404` behavior     Implemented
  Synchronous processing          Implemented
  Fixture-backed scanner          Implemented
  Scanner abstraction             Implemented
  Severity mapping                Implemented
  `min_severity` filtering        Implemented
  Structured errors               Implemented
  OpenAPI contract                Included
  `SPEC.md`                       Included
  README                          Included

The supplied fixture contains 12 Scorecard checks and an aggregate score
of `3.4`.

------------------------------------------------------------------------

# 15. Persistence and Lifecycle

Storage is intentionally in memory:

``` python
SCANS_STORE
```

Therefore:

> Restarting the application removes all previously created scans.

The scan lifecycle is deliberately simple:

``` text
COMPLETED
```

There is no asynchronous job queue, worker, or `PENDING` state because
the assignment explicitly specifies synchronous fixture reads.

------------------------------------------------------------------------

# 16. Done vs Deliberately Omitted

## Done

-   Static bearer-token authentication
-   Admin-only scan creation
-   Viewer/admin read access
-   Strict tenant isolation
-   Cross-tenant `404` behavior
-   Synchronous fixture-backed scanning
-   Scorecard check normalization
-   Deterministic severity mapping
-   Inclusive severity filtering
-   Structured error envelope
-   OpenAPI 3.0.3 contract
-   Specification-first implementation using `SPEC.md`

## Deliberately omitted

The following are outside the assignment scope:

-   Real OpenSSF Scorecard CLI execution
-   Repository cloning
-   Persistent database
-   Background jobs
-   JWT/OAuth authentication
-   Login/registration
-   Frontend
-   Docker/Kubernetes
-   CI/CD
-   Pagination
-   Caching
-   Rate limiting
-   Audit logging
-   LLM-generated reports

------------------------------------------------------------------------

# 17. Known Limitations

1.  **In-memory storage**\
    Scans disappear when the process restarts.

2.  **Fixture-backed scanning**\
    The supplied Scorecard fixture is returned instead of scanning the
    actual repository.

3.  **Static credentials**\
    Tokens are stored locally in `tokens.json` for the exercise.

4.  **Synchronous processing**\
    Scan creation and normalization happen during the HTTP request.

5.  **No automated test suite**\
    The implementation was verified through code/fixture inspection and
    API-level manual verification rather than a full automated test
    suite.

------------------------------------------------------------------------

# 18. Next Two Hours

If this were extended beyond the assignment time box, the next work
would be:

1.  Add automated HTTP tests for authentication, authorization,
    validation, and tenant isolation.
2.  Add contract validation against `openapi.yaml`.
3.  Introduce persistent storage behind a repository interface.
4.  Add fixture-driven tests for every severity boundary (`0`, `2`, `3`,
    `4`, `5`, `7`, `8`, `10`).
5.  Replace the fixture reader with an isolated real Scorecard execution
    adapter.
6.  Add operational protections such as timeouts and resource limits
    around real scanner execution.

------------------------------------------------------------------------

# 19. Specification-First Workflow

The implementation follows the requested specification-first approach:

``` text
SPEC.md
   ↓
openapi.yaml
   ↓
FastAPI implementation
   ↓
Fixture-backed verification
```

`SPEC.md` defines the authorization, normalization, and non-goal
decisions.

`openapi.yaml` defines the HTTP contract independently of the
implementation.

`app/main.py` implements those decisions.

------------------------------------------------------------------------

## Submission Contents

The final submission contains:

``` text
app/
fixtures/
SPEC.md
openapi.yaml
README.md
requirements.txt
tokens.json
.gitignore
```

To run the submission, install the requirements and execute:

``` bash
uvicorn app.main:app --reload
```

Then open:

``` text
http://localhost:8000/docs
```
