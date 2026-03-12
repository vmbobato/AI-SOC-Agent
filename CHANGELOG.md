# Changelog

All notable changes to this project will be documented in this file.

The format loosely follows Keep a Changelog principles and Semantic Versioning.

---

## v0.3.2

### Added
- Repository-level `VERSION` file for centralized app version tracking
- `/health` response now includes `service` and `version`
- Global API response header `X-API-Version` populated from `VERSION`
- Run metadata now includes `service` and `version` for traceability
- Incident markdown report header now includes service/version metadata
- Client-facing quickstart documentation (`docs/client_quickstart.md`)
- Expanded operator API reference with onboarding, schemas, and examples

### Changed
- `/health` version is loaded from the root `VERSION` file instead of hardcoded values
- README execution-flow numbering corrected and API docs links improved
- Client ingestion docs clarified for both `events` and full-file `log_content` workflows

### Fixed
- Artifact download robustness in client flows and metadata linkage consistency

## v0.3.0

### Added
- Initial AI SOC pipeline architecture
- FastAPI control plane for API interaction
- Log ingestion and parsing for NGINX access/error and Elastic Beanstalk logs
- Detection engine with rules for web enumeration, sensitive file probes, brute force attempts, and traffic bursts
- Threat intelligence enrichment layer
- Campaign correlation engine
- Alert generation pipeline
- Report generation with Markdown and JSON outputs
- Optional LLM-powered incident summary support
- Multi-tenant API key authentication
- Synthetic log testing fixtures

### Changed
- Project organized into modular pipeline components including ingestion, detection, threat intelligence, correlation, alert pipeline, and reporting

### Fixed
- N/A
