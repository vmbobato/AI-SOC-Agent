# Project: AI SOC Analyst

## Architecture
- ingestion
- detection_engine
- llm_analysis
- alert_pipeline
- reporting

## Engineering Rules
- every detection must have tests
- logs must remain immutable
- use Python typing
- avoid breaking the pipeline flow between stages

## Documentation Policy

Documentation must always stay synchronized with the codebase.

Whenever code changes affect behavior, architecture, APIs, rules, or configuration,
the corresponding documentation must also be updated.

The following files must be reviewed and updated when relevant:

- README.md
- CHANGELOG.md
- docs/ directory
- architecture documentation
- rule documentation
- API documentation

### Required Documentation Updates

When implementing changes, the agent must:

1. Update **README.md** if:
   - architecture changes
   - new features are added
   - project setup changes
   - new components are introduced

2. Update **CHANGELOG.md** for every functional change using the following categories:
   - Added
   - Changed
   - Fixed
   - Removed

3. Update **docs/** when:
   - new modules or systems are added
   - architecture changes
   - detection logic changes
   - ingestion format changes

4. Add documentation for:
   - new detection rules
   - new parsers
   - new API endpoints
   - new pipeline stages

### Rule Documentation

Every detection rule must include:
- description
- detection logic summary
- expected input logs
- example triggering log
- test coverage

Detection rules must also include:
- at least one unit test
- one realistic synthetic log example

### Changelog Requirement

Every functional change must update `CHANGELOG.md`.

The entry must be placed under the correct version and categorized as:
- Added
- Changed
- Fixed
- Removed

### Failure Condition

A change is considered **incomplete** if documentation is not updated.

Agents must never modify code without checking whether documentation must also be updated.

Pull requests or code changes that modify functionality but do not update documentation are considered invalid.