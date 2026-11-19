
# NETSHADOW — Database Documentation

## 1. Overview

NETSHADOW uses SQLite as its initial relational database engine.

The database stores network information, devices, audit sessions, security findings and generated reports.

The database layer is designed to provide:
- Data consistency.
- Referential integrity.
- Secure query execution.
- Transaction management.
- Reliable persistence.
- Controlled access to stored information.

## 2. Database Technology

| Property | Configuration |
|---|---|
| Database engine | SQLite |
| Python interface | sqlite3 |
| Default database | SQLite file |
| In-memory support | Yes |
| Foreign keys | Enabled |
| Write-ahead logging | Enabled for disk databases |
| Query parameters | Required |

## 3. Database Structure

### 3.1 Networks

Stores known network definitions.

Fields:
- id
- network
- name
- description
- created_at

Purpose:
- Identify network environments.
- Store network descriptions.
- Associate devices with networks.

### 3.2 Devices

Stores information about network devices.

Fields:
- id
- ip_address
- mac_address
- hostname
- vendor
- device_type
- operating_system
- network_id
- created_at
- updated_at

The network_id field references networks.id.

### 3.3 Scans

Stores audit execution records.

Fields:
- id
- target
- mode
- status
- authorization_reference
- started_at
- finished_at
- created_at
- metadata

Possible statuses:
- PENDING
- RUNNING
- COMPLETED
- FAILED
- CANCELLED

### 3.4 Findings

Stores security observations.

Fields:
- id
- title
- description
- severity
- category
- scan_id
- target
- recommendation
- created_at

Findings may be associated with a scan.

### 3.5 Reports

Stores generated audit reports.

Fields:
- id
- title
- report_type
- content
- scan_id
- format
- created_at

Supported report formats:
- JSON
- HTML
- TXT
- PDF

## 4. Relationships

- One network can contain multiple devices.
- One scan can produce multiple findings.
- One scan can generate multiple reports.
- Deleting a parent record follows the configured foreign-key cascade rules.

## 5. Database Layer

The database package contains:

- database.py
- models.py
- session.py
- repositories/

### Database

Responsible for:
- Connection management.
- Schema initialization.
- Query execution.
- Transactions.
- Health checks.
- Database shutdown.

### Models

Models validate and represent application data independently of SQL operations.

### Sessions

Sessions provide controlled access to database operations.

### Repositories

Repositories isolate persistence logic.

Available repositories:
- NetworkRepository
- DeviceRepository
- ScanRepository
- FindingsRepository
- ReportRepository

## 6. Security Requirements

All database operations must follow these rules:

1. Use parameterized SQL queries.
2. Never concatenate untrusted input into SQL statements.
3. Enable foreign-key enforcement.
4. Validate data before persistence.
5. Use transactions for related operations.
6. Avoid logging sensitive information.
7. Restrict database file permissions where supported.
8. Maintain recoverable backups.
9. Handle database errors safely.
10. Validate relationships before inserting records.

## 7. Transactions

Transactions are used when multiple operations must succeed or fail together.

If an operation fails, the transaction must be rolled back.

This prevents partially committed application state.

## 8. Backup and Recovery

Database backups should:
- Be stored separately from the active database.
- Use controlled file permissions.
- Be validated before restoration.
- Avoid overwriting the active database without confirmation.
- Be recorded in the application audit log.

## 9. Migrations

Database schema changes must be versioned.

The schema_metadata table records the current schema version.

Future migrations should:
- Have unique version identifiers.
- Be repeatable only when explicitly designed to be.
- Preserve existing data.
- Support rollback or documented recovery procedures.

## 10. Testing

Database tests should cover:
- Schema initialization.
- CRUD operations.
- Foreign-key constraints.
- Invalid input.
- Transaction rollback.
- Repository behavior.
- Database recovery.
- SQL injection resistance.

Tests should use isolated temporary databases.
