# Multi-Tenant Scan API Specification

## Authorization Rules

Every endpoint requires `Authorization: Bearer <token>`. Tokens are static entries in `tokens.json`; no JWT, login, password, or user store is used. A token maps to a user, tenant, and role. `admin` users may create scans. Both `admin` and `viewer` users may read scans and issues. A scan is owned by the tenant of the authenticated user who created it. Every read operation must verify that the scan tenant equals the caller tenant. If a scan does not exist, or exists for another tenant, return `404 NOT_FOUND` so the API does not reveal another tenant's resource. Missing or unknown tokens return `401 UNAUTHORIZED`; a valid viewer attempting `POST /scans` returns `403 FORBIDDEN`.

## Normalization Rules

`POST /scans` reads the supplied Scorecard fixture synchronously and stores the result in memory; it does not invoke the Scorecard CLI. The fixture's top-level Scorecard score becomes the scan's `aggregate_score`. Each raw check becomes one `SecurityIssue`. `issue_id` is deterministic: `iss_<lowercase-check-name-with-non-alphanumerics-replaced-by-hyphens>`. `check_name` and `score` are copied from the fixture. `title` is the raw check `reason`, `description` is the fixture documentation's short description, and `evidence` is the raw `details` array. `remediation_hint` is a concise deterministic hint based on the check name.

Severity is derived only from score and follows this complete mapping: scores 0-2 are `CRITICAL`, 3-4 are `HIGH`, 5-7 are `MEDIUM`, and 8-10 are `LOW`. The ordering for filtering is `LOW < MEDIUM < HIGH < CRITICAL`; therefore `min_severity=HIGH` returns HIGH and CRITICAL issues. `min_severity` is inclusive. Scores outside 0-10 are invalid fixture data and are treated as an internal error rather than silently remapped.

## Non-Goals

No real Scorecard CLI, external repository cloning, database, job queue, asynchronous scan lifecycle, JWT/OAuth/login flow, user registration, frontend, Docker/Kubernetes, caching, pagination, rate limiting, audit logging, or LLM-generated reports are implemented. Storage is intentionally in-memory and is lost on restart. The fixture is the scanner implementation for this exercise. The API implements only the three required scan endpoints.
