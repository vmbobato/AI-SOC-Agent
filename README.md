# AI SOC Agent

## Overview
AI SOC Agent is an AI-assisted Security Operations Center (SOC) pipeline that analyzes infrastructure logs, detects suspicious activity, and generates automated analyst reports using a local Large Language Model (LLM).

The system parses server logs, detects attack patterns such as web scanning, exploit probing, and traffic bursts, and produces structured incident cases that are summarized into a professional SOC analyst report.

This project demonstrates how AI can augment security analysts by automating log analysis and incident reporting.

---

## Features

* Multi-log parsing (Nginx, application logs, AWS Elastic Beanstalk logs)
* Detection of common web attack behaviors
* Structured incident case generation
* Automated SOC analyst reports using an LLM
* MITRE ATT&CK mapping for detected activity
* Local LLM integration using Ollama

---

## Example Attacks Detected

The system can detect patterns such as:

| Detection | Description |
|----------|--------------|
| **Web Enumaration** | Attackers scanning large numbers of URLs |
| **Sensitive File Probes** | Attempts to access configuration or secret files |
| **Application-Layer Probing** | Repeated attempts blocked by application logic |
| **Traffic Bursts** | Potential DoS behavior |
| **Brute Force Attempts** | Repeated login failures |


---

## Project Architecture

```
Logs
  ↓
Log Parsers
  ↓
Detection Engine
  ↓
Incident Case Builder
  ↓
Case Merger
  ↓
Structured Incident JSON
  ↓
LLM SOC Analyst
  ↓
Markdown Incident Report
```

---

## Detection Engine

The detection engine analyzes parsed log events to identify attack patterns.  

Current detection modules include:

### Web Enumaration Detection

Identifies automated directory scanning.  

Indicators:  
* Large number of unique paths
* High ratio of 404 responses
* Short time window

### Sensitive File Probing

Detects attempts to access sensitive application files.  

Examples:  
```
/phpinfo
/.git/config
/config.yaml
/.env
```

### Applicaation Layer Probing

Detects repeated attempts blocked by applciation logic.

Examples:
```
secret_path
bogus_stack_probe
```

### Traffic Burst Detection

Identifies potential denial-of-service behavior based on request volume.

---

## LLM Integration

The system uses a local LLM via Ollama to convert structured incident data into a human-readable SOC report.  

This allows the system to act as an AI SOC analyst assistant.  

The LLM produces:  
* Executive summary
* Incident breakdown
* Priority assessment
* Recommended actions
* MITRE ATT&CK mapping

---

## Intallation

Clone the repository:  
```
git clone https://github.com/AI-SOC-Agent/ai-soc-agent.git
cd ai-soc-agent
```

Create environment:
```
python3 -m venv .soc_agent
```

If in Linux:
```
source .soc_agent/bin/activate
```

If in Windows:
```
source .soc_agent/Scripts/Activate
```