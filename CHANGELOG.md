# Changelog

All notable changes to this project will be documented in this file.

The format loosely follows Keep a Changelog principles and Semantic Versioning.

---

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
