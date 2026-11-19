
# NETSHADOW — Architecture

## 1. Overview

NETSHADOW is a Network Intelligence & Security Auditing platform developed using Python and Rust.

The platform is designed to help administrators understand, document and assess the security posture of networks and connected devices.

Supported operating systems:
- Windows
- Kali Linux
- Other compatible Linux distributions

## 2. Technology Stack

| Component | Technology |
|---|---|
| Main application | Python |
| Performance components | Rust |
| Python-Rust integration | PyO3 |
| Build system | Maturin |
| Database | SQLite |
| Configuration | YAML |
| Command-line interface | Python |
| Testing | Pytest |

## 3. Architecture Layers

### 3.1 Core

The core controls application execution and communication.

Main components:
- application.py
- orchestrator.py
- event_bus.py
- platform_detector.py
- network_context.py
- permissions.py
- lifecycle.py
- exceptions.py

### 3.2 Interface

The interface provides interaction with the user.

Responsibilities:
- Command-line interface
- Menus
- Console output
- Tables
- Progress indicators
- User commands

### 3.3 Engines

Engines contain the technical processing logic.

Main engines:
- Network Engine
- Discovery Engine
- Port Engine
- Service Engine
- Device Engine
- Security Engine
- Monitoring Engine
- Rust Bridge

### 3.4 Modules

Modules provide higher-level intelligence.

Examples:
- Network Intelligence
- Security Intelligence
- Device Intelligence
- Threat Intelligence
- Anomaly Detection
- Baseline Engine
- AI Security Analyst

### 3.5 Security Layer

The security layer provides protections across the application.

Responsibilities:
- Input validation
- Permission management
- Secrets management
- Secure storage
- Integrity verification
- Audit logging
- Dependency auditing
- Rate limiting
- Privacy management
- Recovery management

## 4. Database Architecture

NETSHADOW uses SQLite as its initial database engine.

Main entities:
- Networks
- Devices
- Scans
- Findings
- Reports

Repositories isolate database operations from the rest of the application.

SQL operations must use parameterized queries.

## 5. Python and Rust Integration

Python controls application logic and orchestration.

Rust provides optional performance-oriented components.

The Rust integration must:
- Be optional.
- Support Python fallback.
- Validate API compatibility.
- Handle errors safely.
- Never silently bypass security controls.

## 6. Operating Modes

### SAFE

Default operating mode.

- Passive information processing.
- No active network auditing by default.
- No actions without explicit authorization.

### AUDIT

Authorized security assessment mode.

- Explicit target scope.
- Authorization reference.
- Controlled execution.
- Timeouts and resource limits.
- Recorded results.

### MONITOR

Monitoring mode.

- Availability tracking.
- Latency measurements.
- Change detection.
- Historical metrics.
- Configurable alerts.

## 7. Security Principles

NETSHADOW follows these principles:

1. Secure by default.
2. Explicit authorization.
3. Least privilege.
4. Input validation.
5. Data minimization.
6. Parameterized database operations.
7. Controlled resource consumption.
8. Auditable operations.
9. No silent privilege escalation.
10. Safe error handling.

## 8. Execution Flow

1. Application initialization.
2. Platform detection.
3. Configuration loading.
4. Security initialization.
5. Database initialization.
6. Permission and scope validation.
7. User interaction.
8. Authorized operation execution.
9. Result processing.
10. Report generation.
11. Resource cleanup.

## 9. Future Development

Planned improvements:
- Local web dashboard.
- Advanced reporting.
- Extended device intelligence.
- Improved anomaly detection.
- Expanded Rust components.
- Additional security integrations.
