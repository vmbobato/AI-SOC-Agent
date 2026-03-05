# AI SOC Incident Report (MVP)

- Generated (UTC): 2026-03-04T17:06:02.781560+00:00
- Cases detected: 74

---
## Case 1: Web Enumeration Scan

**Time window:** 2026-03-04T01:00:00+00:00 → 2026-03-04T01:02:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** Low
**Confidence:** 0.92

### Evidence
- **requests**: 100
- **unique_paths**: 100
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /lms/phpinfo: 1
  - /lms/_profiler/phpinfo: 1
  - /lms/xampp/phpinfo: 1
  - /.local: 1
  - /local.json: 1
  - /login/config.yaml: 1
  - /login/.ftpconfig: 1
  - /login/.git/config: 1
  - /login/.gitlab-ci.yml: 1
  - /login/jenkinsFile: 1
- **status_counts**:
  - 404: 100

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 2: Web Enumeration Scan

**Time window:** 2026-03-04T01:02:00+00:00 → 2026-03-04T01:04:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** Low
**Confidence:** 0.92

### Evidence
- **requests**: 194
- **unique_paths**: 194
- **unique_ratio**: 1.0
- **404_ratio**: 0.9948453608247423
- **top_paths**:
  - /nodeapi/config.env: 1
  - /nodeapi/phpinfo: 1
  - /nodeapi/_profiler/phpinfo: 1
  - /nodeapi/xampp/phpinfo: 1
  - /node/config.env: 1
  - /node.js: 1
  - /Node.js/JavaScript: 1
  - /node/phpinfo: 1
  - /node/_profiler/phpinfo: 1
  - /node/xampp/phpinfo: 1
- **status_counts**:
  - 404: 193
  - 200: 1

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 3: Web Enumeration Scan

**Time window:** 2026-03-04T01:04:00+00:00 → 2026-03-04T01:06:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** Medium
**Confidence:** 0.92

### Evidence
- **requests**: 269
- **unique_paths**: 269
- **unique_ratio**: 1.0
- **404_ratio**: 0.9962825278810409
- **top_paths**:
  - /qa/phpinfo: 1
  - /qa/_profiler/phpinfo: 1
  - /qa/xampp/phpinfo: 1
  - /?q=info: 1
  - /.rbenv-gemsets: 1
  - /.rbenv-version: 1
  - /.remote: 1
  - /remote-sync.json: 1
  - /resources/config.yaml: 1
  - /resources/.ftpconfig: 1
- **status_counts**:
  - 404: 268
  - 200: 1

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 4: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:04:00+00:00 → 2026-03-04T01:06:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 269
- **top_paths**:
  - /qa/phpinfo: 1
  - /qa/_profiler/phpinfo: 1
  - /qa/xampp/phpinfo: 1
  - /?q=info: 1
  - /.rbenv-gemsets: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 5: Web Enumeration Scan

**Time window:** 2026-03-04T01:06:00+00:00 → 2026-03-04T01:08:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** Low
**Confidence:** 0.92

### Evidence
- **requests**: 84
- **unique_paths**: 84
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /testing/config.env: 1
  - /testing/phpinfo: 1
  - /testing/_profiler/phpinfo: 1
  - /testing/xampp/phpinfo: 1
  - /test.js: 1
  - /test/phpinfo: 1
  - /testphpinfo: 1
  - /test/_profiler/phpinfo: 1
  - /tests/config.env: 1
  - /tests/phpinfo: 1
- **status_counts**:
  - 404: 84

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 6: Web Enumeration Scan

**Time window:** 2026-03-04T01:08:00+00:00 → 2026-03-04T01:10:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 721
- **unique_paths**: 721
- **unique_ratio**: 1.0
- **404_ratio**: 0.9972260748959778
- **top_paths**:
  - /xampp/phpinfo: 1
  - /?xdebuginfo: 1
  - /.zshenv: 1
  - /constants.js: 1
  - /environments/production.rb: 1
  - /production.rb: 1
  - /development.json: 1
  - /main/resources/appsettings.yml: 1
  - /resources/appsettings.yml: 1
  - /appsettings.yml: 1
- **status_counts**:
  - 404: 719
  - 200: 2

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 7: Brute Force Attempt

**Time window:** 2026-03-04T01:08:00+00:00 → 2026-03-04T01:10:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 424
- **fail_ratio**: 0.0
- **top_paths**:
  - /admin/dashboard/: 1
  - /dashboard/admin: 1
  - /admin-app: 1
  - /adminer: 1
  - /plugins/fluent-smtp/assets/admin/js/fluent-mail-admin-app.js: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 8: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:08:00+00:00 → 2026-03-04T01:10:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 721
- **top_paths**:
  - /xampp/phpinfo: 1
  - /?xdebuginfo: 1
  - /.zshenv: 1
  - /constants.js: 1
  - /environments/production.rb: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 9: Web Enumeration Scan

**Time window:** 2026-03-04T01:10:00+00:00 → 2026-03-04T01:12:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 733
- **unique_paths**: 733
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /admin/license.crt: 1
  - /admin/license.env: 1
  - /admin/license.gz: 1
  - /admin/license.inc: 1
  - /admin/license.js: 1
  - /admin/license.json: 1
  - /admin/license.key: 1
  - /admin/license.map: 1
  - /admin/license.md: 1
  - /admin/license.old: 1
- **status_counts**:
  - 404: 733

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 10: Brute Force Attempt

**Time window:** 2026-03-04T01:10:00+00:00 → 2026-03-04T01:12:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 379
- **fail_ratio**: 0.0
- **top_paths**:
  - /admin/license.crt: 1
  - /admin/license.env: 1
  - /admin/license.gz: 1
  - /admin/license.inc: 1
  - /admin/license.js: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 11: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:10:00+00:00 → 2026-03-04T01:12:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 733
- **top_paths**:
  - /admin/license.crt: 1
  - /admin/license.env: 1
  - /admin/license.gz: 1
  - /admin/license.inc: 1
  - /admin/license.js: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 12: Web Enumeration Scan

**Time window:** 2026-03-04T01:12:00+00:00 → 2026-03-04T01:14:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 644
- **unique_paths**: 644
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /api/index.json: 1
  - /api/index.key: 1
  - /api/index.map: 1
  - /api/index.md: 1
  - /api/index.old: 1
  - /api/index.pem: 1
  - /api/index.py: 1
  - /api/index.rb: 1
  - /api/index.save: 1
  - /api/index.sql: 1
- **status_counts**:
  - 404: 644

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 13: Brute Force Attempt

**Time window:** 2026-03-04T01:12:00+00:00 → 2026-03-04T01:14:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 384
- **fail_ratio**: 0.0
- **top_paths**:
  - /login/: 1
  - /api/login: 1
  - /api/admin/: 1
  - /api/auth/: 1
  - /api/login/: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 14: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:12:00+00:00 → 2026-03-04T01:14:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 644
- **top_paths**:
  - /api/index.json: 1
  - /api/index.key: 1
  - /api/index.map: 1
  - /api/index.md: 1
  - /api/index.old: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 15: Web Enumeration Scan

**Time window:** 2026-03-04T01:14:00+00:00 → 2026-03-04T01:16:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 626
- **unique_paths**: 626
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /admin/data/db.ts: 1
  - /admin/data/db.txt: 1
  - /admin/data/db.xml: 1
  - /admin/data/db.yaml: 1
  - /admin/data/db.yml: 1
  - /admin/data/debug.env: 1
  - /admin/data/debug.js: 1
  - /admin/data/debug.json: 1
  - /admin/data/debug.old: 1
  - /admin/data/debug.sql: 1
- **status_counts**:
  - 404: 626

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 16: Brute Force Attempt

**Time window:** 2026-03-04T01:14:00+00:00 → 2026-03-04T01:16:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 626
- **fail_ratio**: 0.0
- **top_paths**:
  - /admin/data/db.ts: 1
  - /admin/data/db.txt: 1
  - /admin/data/db.xml: 1
  - /admin/data/db.yaml: 1
  - /admin/data/db.yml: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 17: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:14:00+00:00 → 2026-03-04T01:16:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 626
- **top_paths**:
  - /admin/data/db.ts: 1
  - /admin/data/db.txt: 1
  - /admin/data/db.xml: 1
  - /admin/data/db.yaml: 1
  - /admin/data/db.yml: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 18: Web Enumeration Scan

**Time window:** 2026-03-04T01:16:00+00:00 → 2026-03-04T01:18:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 613
- **unique_paths**: 613
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /admin/json/readme.xml: 1
  - /admin/json/readme.yml: 1
  - /admin/json/readme.zip: 1
  - /admin/json/sample.json: 1
  - /admin/json/sample.old: 1
  - /admin/json/sample.tar.gz: 1
  - /admin/json/sample.yaml: 1
  - /admin/json/sample.yml: 1
  - /admin/json/sample.zip: 1
  - /admin/json/secret.js: 1
- **status_counts**:
  - 404: 613

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 19: Brute Force Attempt

**Time window:** 2026-03-04T01:16:00+00:00 → 2026-03-04T01:18:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 613
- **fail_ratio**: 0.0
- **top_paths**:
  - /admin/json/readme.xml: 1
  - /admin/json/readme.yml: 1
  - /admin/json/readme.zip: 1
  - /admin/json/sample.json: 1
  - /admin/json/sample.old: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 20: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:16:00+00:00 → 2026-03-04T01:18:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 613
- **top_paths**:
  - /admin/json/readme.xml: 1
  - /admin/json/readme.yml: 1
  - /admin/json/readme.zip: 1
  - /admin/json/sample.json: 1
  - /admin/json/sample.old: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 21: Web Enumeration Scan

**Time window:** 2026-03-04T01:18:00+00:00 → 2026-03-04T01:20:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 620
- **unique_paths**: 620
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /admin/old/users.ts: 1
  - /admin/old/users.txt: 1
  - /admin/old/users.xml: 1
  - /admin/old/users.yaml: 1
  - /admin/old/users.yml: 1
  - /admin/old/users.zip: 1
  - /admin/old/wp-config.env: 1
  - /admin/old/wp-config.tar.gz: 1
  - /admin/old/wp-config.ts: 1
  - /admin/old/wp-config.zip: 1
- **status_counts**:
  - 404: 620

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 22: Brute Force Attempt

**Time window:** 2026-03-04T01:18:00+00:00 → 2026-03-04T01:20:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 620
- **fail_ratio**: 0.0
- **top_paths**:
  - /admin/old/users.ts: 1
  - /admin/old/users.txt: 1
  - /admin/old/users.xml: 1
  - /admin/old/users.yaml: 1
  - /admin/old/users.yml: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 23: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:18:00+00:00 → 2026-03-04T01:20:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 620
- **top_paths**:
  - /admin/old/users.ts: 1
  - /admin/old/users.txt: 1
  - /admin/old/users.xml: 1
  - /admin/old/users.yaml: 1
  - /admin/old/users.yml: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 24: Web Enumeration Scan

**Time window:** 2026-03-04T01:20:00+00:00 → 2026-03-04T01:22:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 642
- **unique_paths**: 642
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /admin/secrets/login.ts: 1
  - /admin/secrets/login.txt: 1
  - /admin/secrets/login.xml: 1
  - /admin/secrets/login.yml: 1
  - /admin/secrets/login.zip: 1
  - /admin/secrets/main.env: 1
  - /admin/secrets/main.js: 1
  - /admin/secrets/main.json: 1
  - /admin/secrets/main.old: 1
  - /admin/secrets/main.sql: 1
- **status_counts**:
  - 404: 642

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 25: Brute Force Attempt

**Time window:** 2026-03-04T01:20:00+00:00 → 2026-03-04T01:22:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 642
- **fail_ratio**: 0.0
- **top_paths**:
  - /admin/secrets/login.ts: 1
  - /admin/secrets/login.txt: 1
  - /admin/secrets/login.xml: 1
  - /admin/secrets/login.yml: 1
  - /admin/secrets/login.zip: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 26: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:20:00+00:00 → 2026-03-04T01:22:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 642
- **top_paths**:
  - /admin/secrets/login.ts: 1
  - /admin/secrets/login.txt: 1
  - /admin/secrets/login.xml: 1
  - /admin/secrets/login.yml: 1
  - /admin/secrets/login.zip: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 27: Web Enumeration Scan

**Time window:** 2026-03-04T01:22:00+00:00 → 2026-03-04T01:24:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 631
- **unique_paths**: 631
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /admin/test/wp-config.ts: 1
  - /admin/test/wp-config.xml: 1
  - /admin/test/wp-config.yaml: 1
  - /admin/test/wp-config.zip: 1
  - /admin/tmp/config.env: 1
  - /admin/tmp/config.js: 1
  - /admin/tmp/config.old: 1
  - /admin/tmp/config.sql: 1
  - /admin/tmp/config.tar.gz: 1
  - /admin/tmp/config.txt: 1
- **status_counts**:
  - 404: 631

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 28: Brute Force Attempt

**Time window:** 2026-03-04T01:22:00+00:00 → 2026-03-04T01:24:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 376
- **fail_ratio**: 0.0
- **top_paths**:
  - /admin/test/wp-config.ts: 1
  - /admin/test/wp-config.xml: 1
  - /admin/test/wp-config.yaml: 1
  - /admin/test/wp-config.zip: 1
  - /admin/tmp/config.env: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 29: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:22:00+00:00 → 2026-03-04T01:24:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 631
- **top_paths**:
  - /admin/test/wp-config.ts: 1
  - /admin/test/wp-config.xml: 1
  - /admin/test/wp-config.yaml: 1
  - /admin/test/wp-config.zip: 1
  - /admin/tmp/config.env: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 30: Web Enumeration Scan

**Time window:** 2026-03-04T01:24:00+00:00 → 2026-03-04T01:26:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 645
- **unique_paths**: 645
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /api/config/readme.js: 1
  - /api/config/readme.old: 1
  - /api/config/readme.sql: 1
  - /api/config/readme.txt: 1
  - /api/config/readme.xml: 1
  - /api/config/readme.yml: 1
  - /api/config/readme.zip: 1
  - /api/config/sample.js: 1
  - /api/config/sample.sql: 1
  - /api/config/sample.ts: 1
- **status_counts**:
  - 404: 645

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 31: Brute Force Attempt

**Time window:** 2026-03-04T01:24:00+00:00 → 2026-03-04T01:26:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 30
- **fail_ratio**: 0.0
- **top_paths**:
  - /api/data/login.js: 1
  - /api/data/login.sql: 1
  - /api/data/login.tar.gz: 1
  - /api/data/login.ts: 1
  - /api/data/login.txt: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 32: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:24:00+00:00 → 2026-03-04T01:26:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 645
- **top_paths**:
  - /api/config/readme.js: 1
  - /api/config/readme.old: 1
  - /api/config/readme.sql: 1
  - /api/config/readme.txt: 1
  - /api/config/readme.xml: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 33: Web Enumeration Scan

**Time window:** 2026-03-04T01:26:00+00:00 → 2026-03-04T01:28:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 647
- **unique_paths**: 647
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /api/json/debug.env: 1
  - /api/json/debug.js: 1
  - /api/json/debug.old: 1
  - /api/json/debug.sql: 1
  - /api/json/debug.ts: 1
  - /api/json/debug.txt: 1
  - /api/json/debug.xml: 1
  - /api/json/debug.yaml: 1
  - /api/json/debug.yml: 1
  - /api/json/debug.zip: 1
- **status_counts**:
  - 404: 647

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 34: Brute Force Attempt

**Time window:** 2026-03-04T01:26:00+00:00 → 2026-03-04T01:28:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 54
- **fail_ratio**: 0.0
- **top_paths**:
  - /api/json/login.env: 1
  - /api/json/login.json: 1
  - /api/json/login.old: 1
  - /api/json/login.sql: 1
  - /api/json/login.tar.gz: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 35: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:26:00+00:00 → 2026-03-04T01:28:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 647
- **top_paths**:
  - /api/json/debug.env: 1
  - /api/json/debug.js: 1
  - /api/json/debug.old: 1
  - /api/json/debug.sql: 1
  - /api/json/debug.ts: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 36: Web Enumeration Scan

**Time window:** 2026-03-04T01:28:00+00:00 → 2026-03-04T01:30:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 630
- **unique_paths**: 630
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /api/old/settings.sql: 1
  - /api/old/settings.tar.gz: 1
  - /api/old/settings.ts: 1
  - /api/old/settings.txt: 1
  - /api/old/settings.xml: 1
  - /api/old/settings.zip: 1
  - /api/old/site.env: 1
  - /api/old/site.js: 1
  - /api/old/site.sql: 1
  - /api/old/site.tar.gz: 1
- **status_counts**:
  - 404: 630

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 37: Brute Force Attempt

**Time window:** 2026-03-04T01:28:00+00:00 → 2026-03-04T01:30:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 30
- **fail_ratio**: 0.0
- **top_paths**:
  - /api/php/login.env: 1
  - /api/php/login.js: 1
  - /api/php/login.sql: 1
  - /api/php/login.ts: 1
  - /api/php/login.txt: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 38: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:28:00+00:00 → 2026-03-04T01:30:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 630
- **top_paths**:
  - /api/old/settings.sql: 1
  - /api/old/settings.tar.gz: 1
  - /api/old/settings.ts: 1
  - /api/old/settings.txt: 1
  - /api/old/settings.xml: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 39: Web Enumeration Scan

**Time window:** 2026-03-04T01:30:00+00:00 → 2026-03-04T01:32:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 619
- **unique_paths**: 619
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /api/secrets/env.ts: 1
  - /api/secrets/env.txt: 1
  - /api/secrets/env.xml: 1
  - /api/secrets/env.yaml: 1
  - /api/secrets/env.yml: 1
  - /api/secrets/index.env: 1
  - /api/secrets/index.json: 1
  - /api/secrets/index.old: 1
  - /api/secrets/index.sql: 1
  - /api/secrets/index.tar.gz: 1
- **status_counts**:
  - 404: 619

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 40: Brute Force Attempt

**Time window:** 2026-03-04T01:30:00+00:00 → 2026-03-04T01:32:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 36
- **fail_ratio**: 0.0
- **top_paths**:
  - /api/secrets/login.env: 1
  - /api/secrets/login.js: 1
  - /api/secrets/login.json: 1
  - /api/secrets/login.old: 1
  - /api/secrets/login.sql: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 41: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:30:00+00:00 → 2026-03-04T01:32:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 619
- **top_paths**:
  - /api/secrets/env.ts: 1
  - /api/secrets/env.txt: 1
  - /api/secrets/env.xml: 1
  - /api/secrets/env.yaml: 1
  - /api/secrets/env.yml: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 42: Web Enumeration Scan

**Time window:** 2026-03-04T01:32:00+00:00 → 2026-03-04T01:34:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 632
- **unique_paths**: 632
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /api/test/sample.old: 1
  - /api/test/sample.sql: 1
  - /api/test/sample.tar.gz: 1
  - /api/test/sample.ts: 1
  - /api/test/sample.xml: 1
  - /api/test/sample.yaml: 1
  - /api/test/sample.zip: 1
  - /api/test/secret.env: 1
  - /api/test/secret.js: 1
  - /api/test/secret.json: 1
- **status_counts**:
  - 404: 632

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 43: Brute Force Attempt

**Time window:** 2026-03-04T01:32:00+00:00 → 2026-03-04T01:34:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 22
- **fail_ratio**: 0.0
- **top_paths**:
  - /api/tmp/login.env: 1
  - /api/tmp/login.js: 1
  - /api/tmp/login.json: 1
  - /api/tmp/login.yaml: 1
  - /api/tmp/login.yml: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 44: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:32:00+00:00 → 2026-03-04T01:34:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 632
- **top_paths**:
  - /api/test/sample.old: 1
  - /api/test/sample.sql: 1
  - /api/test/sample.tar.gz: 1
  - /api/test/sample.ts: 1
  - /api/test/sample.xml: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 45: Web Enumeration Scan

**Time window:** 2026-03-04T01:34:00+00:00 → 2026-03-04T01:36:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 628
- **unique_paths**: 628
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /config/backup/debug.yml: 1
  - /config/backup/debug.zip: 1
  - /config/backup/default.env: 1
  - /config/backup/default.js: 1
  - /config/backup/default.json: 1
  - /config/backup/default.old: 1
  - /config/backup/default.tar.gz: 1
  - /config/backup/default.txt: 1
  - /config/backup/default.xml: 1
  - /config/backup/default.yaml: 1
- **status_counts**:
  - 404: 628

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 46: Brute Force Attempt

**Time window:** 2026-03-04T01:34:00+00:00 → 2026-03-04T01:36:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 38
- **fail_ratio**: 0.0
- **top_paths**:
  - /config/backup/login.js: 1
  - /config/backup/login.old: 1
  - /config/backup/login.sql: 1
  - /config/backup/login.tar.gz: 1
  - /config/backup/login.ts: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 47: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:34:00+00:00 → 2026-03-04T01:36:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 628
- **top_paths**:
  - /config/backup/debug.yml: 1
  - /config/backup/debug.zip: 1
  - /config/backup/default.env: 1
  - /config/backup/default.js: 1
  - /config/backup/default.json: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 48: Web Enumeration Scan

**Time window:** 2026-03-04T01:36:00+00:00 → 2026-03-04T01:38:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 631
- **unique_paths**: 631
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /config/db/main.yaml: 1
  - /config/db/main.yml: 1
  - /config/db/main.zip: 1
  - /config/db/readme.env: 1
  - /config/db/readme.js: 1
  - /config/db/readme.json: 1
  - /config/db/readme.old: 1
  - /config/db/readme.sql: 1
  - /config/db/readme.tar.gz: 1
  - /config/db/readme.ts: 1
- **status_counts**:
  - 404: 631

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 49: Brute Force Attempt

**Time window:** 2026-03-04T01:36:00+00:00 → 2026-03-04T01:38:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 30
- **fail_ratio**: 0.0
- **top_paths**:
  - /config/env/login.env: 1
  - /config/env/login.js: 1
  - /config/env/login.old: 1
  - /config/env/login.sql: 1
  - /config/env/login.tar.gz: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 50: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:36:00+00:00 → 2026-03-04T01:38:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 631
- **top_paths**:
  - /config/db/main.yaml: 1
  - /config/db/main.yml: 1
  - /config/db/main.zip: 1
  - /config/db/readme.env: 1
  - /config/db/readme.js: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 51: Web Enumeration Scan

**Time window:** 2026-03-04T01:38:00+00:00 → 2026-03-04T01:40:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 613
- **unique_paths**: 613
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /config/keys/site.yaml: 1
  - /config/keys/site.zip: 1
  - /config/keys/test.env: 1
  - /config/keys/test.js: 1
  - /config/keys/test.old: 1
  - /config/keys/test.tar.gz: 1
  - /config/keys/test.txt: 1
  - /config/keys/test.yaml: 1
  - /config/keys/test.zip: 1
  - /config/keys/users.env: 1
- **status_counts**:
  - 404: 613

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 52: Brute Force Attempt

**Time window:** 2026-03-04T01:38:00+00:00 → 2026-03-04T01:40:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 42
- **fail_ratio**: 0.0
- **top_paths**:
  - /config/login.env: 1
  - /config/login.js: 1
  - /config/login.json: 1
  - /config/login.old: 1
  - /config/login.sql: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 53: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:38:00+00:00 → 2026-03-04T01:40:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 613
- **top_paths**:
  - /config/keys/site.yaml: 1
  - /config/keys/site.zip: 1
  - /config/keys/test.env: 1
  - /config/keys/test.js: 1
  - /config/keys/test.old: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 54: Web Enumeration Scan

**Time window:** 2026-03-04T01:40:00+00:00 → 2026-03-04T01:42:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 622
- **unique_paths**: 622
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /config/private/debug.old: 1
  - /config/private/debug.sql: 1
  - /config/private/debug.tar.gz: 1
  - /config/private/debug.ts: 1
  - /config/private/debug.txt: 1
  - /config/private/debug.xml: 1
  - /config/private/debug.yaml: 1
  - /config/private/debug.yml: 1
  - /config/private/debug.zip: 1
  - /config/private/default.env: 1
- **status_counts**:
  - 404: 622

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 55: Brute Force Attempt

**Time window:** 2026-03-04T01:40:00+00:00 → 2026-03-04T01:42:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 30
- **fail_ratio**: 0.0
- **top_paths**:
  - /config/private/login.env: 1
  - /config/private/login.js: 1
  - /config/private/login.json: 1
  - /config/private/login.old: 1
  - /config/private/login.sql: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 56: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:40:00+00:00 → 2026-03-04T01:42:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 622
- **top_paths**:
  - /config/private/debug.old: 1
  - /config/private/debug.sql: 1
  - /config/private/debug.tar.gz: 1
  - /config/private/debug.ts: 1
  - /config/private/debug.txt: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 57: Web Enumeration Scan

**Time window:** 2026-03-04T01:42:00+00:00 → 2026-03-04T01:44:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 607
- **unique_paths**: 607
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /config/sql/info.tar.gz: 1
  - /config/sql/info.ts: 1
  - /config/sql/info.xml: 1
  - /config/sql/info.yaml: 1
  - /config/sql/info.yml: 1
  - /config/sql/log.env: 1
  - /config/sql/log.js: 1
  - /config/sql/log.json: 1
  - /config/sql/log.old: 1
  - /config/sql/log.sql: 1
- **status_counts**:
  - 404: 607

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 58: Brute Force Attempt

**Time window:** 2026-03-04T01:42:00+00:00 → 2026-03-04T01:44:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 36
- **fail_ratio**: 0.0
- **top_paths**:
  - /config/sql/login.env: 1
  - /config/sql/login.js: 1
  - /config/sql/login.json: 1
  - /config/sql/login.old: 1
  - /config/sql/login.sql: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 59: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:42:00+00:00 → 2026-03-04T01:44:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 607
- **top_paths**:
  - /config/sql/info.tar.gz: 1
  - /config/sql/info.ts: 1
  - /config/sql/info.xml: 1
  - /config/sql/info.yaml: 1
  - /config/sql/info.yml: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 60: Web Enumeration Scan

**Time window:** 2026-03-04T01:44:00+00:00 → 2026-03-04T01:46:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 590
- **unique_paths**: 590
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /config/tmp/site.ts: 1
  - /config/tmp/site.txt: 1
  - /config/tmp/site.xml: 1
  - /config/tmp/site.yaml: 1
  - /config/tmp/site.yml: 1
  - /config/tmp/site.zip: 1
  - /config/tmp/test.js: 1
  - /config/tmp/test.json: 1
  - /config/tmp/test.old: 1
  - /config/tmp/test.sql: 1
- **status_counts**:
  - 404: 590

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 61: Brute Force Attempt

**Time window:** 2026-03-04T01:44:00+00:00 → 2026-03-04T01:46:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 32
- **fail_ratio**: 0.0
- **top_paths**:
  - /config/upload/login.env: 1
  - /config/upload/login.js: 1
  - /config/upload/login.json: 1
  - /config/upload/login.sql: 1
  - /config/upload/login.tar.gz: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 62: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:44:00+00:00 → 2026-03-04T01:46:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 590
- **top_paths**:
  - /config/tmp/site.ts: 1
  - /config/tmp/site.txt: 1
  - /config/tmp/site.xml: 1
  - /config/tmp/site.yaml: 1
  - /config/tmp/site.yml: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 63: Web Enumeration Scan

**Time window:** 2026-03-04T01:46:00+00:00 → 2026-03-04T01:48:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 616
- **unique_paths**: 616
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /core/data/config.json: 1
  - /core/data/config.old: 1
  - /core/data/config.sql: 1
  - /core/data/config.tar.gz: 1
  - /core/data/config.ts: 1
  - /core/data/config.txt: 1
  - /core/data/config.xml: 1
  - /core/data/config.yaml: 1
  - /core/data/config.zip: 1
  - /core/data/database.env: 1
- **status_counts**:
  - 404: 616

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 64: Brute Force Attempt

**Time window:** 2026-03-04T01:46:00+00:00 → 2026-03-04T01:48:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 27
- **fail_ratio**: 0.0
- **top_paths**:
  - /core/data/login.env: 1
  - /core/data/login.js: 1
  - /core/data/login.json: 1
  - /core/data/login.sql: 1
  - /core/data/login.tar.gz: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 65: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:46:00+00:00 → 2026-03-04T01:48:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 616
- **top_paths**:
  - /core/data/config.json: 1
  - /core/data/config.old: 1
  - /core/data/config.sql: 1
  - /core/data/config.tar.gz: 1
  - /core/data/config.ts: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 66: Web Enumeration Scan

**Time window:** 2026-03-04T01:48:00+00:00 → 2026-03-04T01:50:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 617
- **unique_paths**: 617
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /core/json/db.xml: 1
  - /core/json/db.yaml: 1
  - /core/json/db.zip: 1
  - /core/json/debug.js: 1
  - /core/json/debug.json: 1
  - /core/json/debug.old: 1
  - /core/json/debug.sql: 1
  - /core/json/debug.tar.gz: 1
  - /core/json/debug.ts: 1
  - /core/json/debug.txt: 1
- **status_counts**:
  - 404: 617

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 67: Brute Force Attempt

**Time window:** 2026-03-04T01:48:00+00:00 → 2026-03-04T01:50:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 46
- **fail_ratio**: 0.0
- **top_paths**:
  - /core/json/login.js: 1
  - /core/json/login.json: 1
  - /core/json/login.old: 1
  - /core/json/login.sql: 1
  - /core/json/login.tar.gz: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 68: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:48:00+00:00 → 2026-03-04T01:50:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 617
- **top_paths**:
  - /core/json/db.xml: 1
  - /core/json/db.yaml: 1
  - /core/json/db.zip: 1
  - /core/json/debug.js: 1
  - /core/json/debug.json: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 69: Web Enumeration Scan

**Time window:** 2026-03-04T01:50:00+00:00 → 2026-03-04T01:52:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.92

### Evidence
- **requests**: 645
- **unique_paths**: 645
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /core/old/readme.env: 1
  - /core/old/readme.old: 1
  - /core/old/readme.sql: 1
  - /core/old/readme.tar.gz: 1
  - /core/old/readme.ts: 1
  - /core/old/readme.txt: 1
  - /core/old/readme.xml: 1
  - /core/old/readme.yaml: 1
  - /core/old/readme.yml: 1
  - /core/old/readme.zip: 1
- **status_counts**:
  - 404: 645

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 70: Brute Force Attempt

**Time window:** 2026-03-04T01:50:00+00:00 → 2026-03-04T01:52:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 32
- **fail_ratio**: 0.0
- **top_paths**:
  - /core/php/login.env: 1
  - /core/php/login.js: 1
  - /core/php/login.old: 1
  - /core/php/login.sql: 1
  - /core/php/login.tar.gz: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 71: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:50:00+00:00 → 2026-03-04T01:52:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 645
- **top_paths**:
  - /core/old/readme.env: 1
  - /core/old/readme.old: 1
  - /core/old/readme.sql: 1
  - /core/old/readme.tar.gz: 1
  - /core/old/readme.ts: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage

---
## Case 72: Web Enumeration Scan

**Time window:** 2026-03-04T01:52:00+00:00 → 2026-03-04T01:54:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** Medium
**Confidence:** 0.92

### Evidence
- **requests**: 479
- **unique_paths**: 479
- **unique_ratio**: 1.0
- **404_ratio**: 1.0
- **top_paths**:
  - /core/secrets/db.env: 1
  - /core/secrets/db.js: 1
  - /core/secrets/db.json: 1
  - /core/secrets/db.old: 1
  - /core/secrets/db.sql: 1
  - /core/secrets/db.tar.gz: 1
  - /core/secrets/db.ts: 1
  - /core/secrets/db.txt: 1
  - /core/secrets/db.xml: 1
  - /core/secrets/db.zip: 1
- **status_counts**:
  - 404: 479

### Recommended Actions
- Block offending IP via AWS WAF (or ALB/WAF) if persistent.
- Enable rate limiting (AWS WAF rate-based rule is ideal).
- Add managed rules / bot protections if available.
- Alert if any scan/probe path returns 200/302 (possible exposure).

---
## Case 73: Brute Force Attempt

**Time window:** 2026-03-04T01:52:00+00:00 → 2026-03-04T01:54:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.8

### Evidence
- **login_attempts**: 28
- **fail_ratio**: 0.0
- **top_paths**:
  - /core/secrets/login.env: 1
  - /core/secrets/login.json: 1
  - /core/secrets/login.sql: 1
  - /core/secrets/login.tar.gz: 1
  - /core/secrets/login.ts: 1

### Recommended Actions
- Enable login rate limiting
- Enable MFA
- Block repeated offenders

---
## Case 74: Traffic Burst / Possible DoS

**Time window:** 2026-03-04T01:52:00+00:00 → 2026-03-04T01:54:00+00:00

**Source IP(s):** 84.247.182.240

**Severity:** High
**Confidence:** 0.85

### Evidence
- **requests**: 479
- **top_paths**:
  - /core/secrets/db.env: 1
  - /core/secrets/db.js: 1
  - /core/secrets/db.json: 1
  - /core/secrets/db.old: 1
  - /core/secrets/db.sql: 1

### Recommended Actions
- Enable rate limiting
- Block offending IP
- Check server resource usage
