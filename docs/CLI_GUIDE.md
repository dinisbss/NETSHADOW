
# NETSHADOW — CLI User Guide

## 1. Introduction

The NETSHADOW Command-Line Interface (CLI) provides access to the platform's network intelligence, security auditing and monitoring capabilities.

The interface is designed to be clear, structured and accessible.

## 2. Starting the Application

From the project root, activate the virtual environment.

Windows:

```powershell
.\.venv\Scripts\Activate.ps1
py main.py
```

Kali Linux:

```bash
source .venv/bin/activate
python main.py
```

For available command-line arguments:

```bash
python main.py --help
```

## 3. Main Interface

The CLI provides access to the following areas:

- Network management.
- Device information.
- Audit management.
- Monitoring.
- Reports.
- Settings.

The available options depend on the implemented application commands.

## 4. Network Management

The network section manages network information.

Typical operations:
- View configured networks.
- Add a network definition.
- Inspect network information.
- Review network configuration.
- Associate devices with networks.

Network selection does not establish authorization for active auditing.

## 5. Device Management

The device section provides access to stored device information.

Available information may include:
- IP address.
- MAC address.
- Hostname.
- Vendor.
- Device type.
- Operating system.
- Associated network.

## 6. Operating Modes

### SAFE

Default mode.

Designed for passive information processing and local analysis.

### AUDIT

Used for explicitly authorized security assessments.

Before an audit:
- Confirm authorization.
- Define the permitted scope.
- Review the operation.
- Respect configured limits.

### MONITOR

Used for observing network availability, latency and changes over time.

## 7. Audit Management

The audit section manages audit records and their results.

An audit record may contain:
- Target.
- Operating mode.
- Authorization reference.
- Execution status.
- Start and finish timestamps.
- Metadata.

Possible statuses:

- PENDING
- RUNNING
- COMPLETED
- FAILED
- CANCELLED

## 8. Monitoring

The monitoring section provides access to:

- Availability information.
- Latency metrics.
- Historical measurements.
- Change detection.
- Alerts.

Monitoring must respect the configured target scope and resource limits.

## 9. Reports

The reports section manages generated security reports.

Supported formats:

- JSON
- HTML
- TXT
- PDF

Reports may contain:
- Audit information.
- Devices.
- Findings.
- Severity classifications.
- Recommendations.
- Execution metadata.

Sensitive information should be excluded unless necessary and authorized.

## 10. Settings

The settings section provides access to application configuration.

Configuration areas include:
- General settings.
- Logging.
- Security.
- Network definitions.
- Application defaults.

Changes to security-related settings should be reviewed carefully.

## 11. Error Handling

When an error occurs:

1. Read the displayed message.
2. Review the relevant configuration.
3. Check the application logs.
4. Verify the required permissions.
5. Retry only after resolving the underlying issue.

Sensitive internal information must not be exposed in error messages.

## 12. Responsible Usage

NETSHADOW is intended for authorized network administration and security auditing.

Never assume that an accessible system is automatically authorized for assessment.

Always respect the approved scope and applicable policies.
