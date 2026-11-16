# TriageIQ — Entity Relationship Diagram

Paste this block into https://mermaid.live to render it, or view it directly in any
Markdown viewer that supports Mermaid (GitHub does, natively).

```mermaid
erDiagram
    ORGANIZATION ||--o{ USER : "has"
    ORGANIZATION ||--o{ ASSET : "owns"
    ORGANIZATION ||--o{ ASSET_GROUP : "owns"
    ORGANIZATION ||--o{ SCAN_IMPORT : "uploads"
    ORGANIZATION ||--o{ REPORT : "generates"
    ORGANIZATION ||--o{ AUDIT_LOG : "logs"
    ORGANIZATION ||--o{ NOTIFICATION : "receives"

    ASSET_GROUP ||--o{ ASSET : "groups"
    ASSET ||--o{ VULNERABILITY : "has findings"

    CVE ||--o{ VULNERABILITY : "enriches (nullable)"
    SCAN_IMPORT ||--o{ VULNERABILITY : "created by"

    VULNERABILITY ||--o{ RISK_SCORE : "scored over time"
    VULNERABILITY ||--o{ REMEDIATION_TASK : "tracked by"

    USER ||--o{ REMEDIATION_TASK : "assigned to"
    USER ||--o{ SCAN_IMPORT : "uploaded by"
    USER ||--o{ NOTIFICATION : "notified"

    ORGANIZATION {
        string id PK
        string name
        string slug
    }
    USER {
        string id PK
        string org_id FK
        string email
        string role
        bool is_active
    }
    ASSET {
        string id PK
        string org_id FK
        string group_id FK
        string hostname
        string criticality
        string environment
        bool internet_facing
    }
    CVE {
        string cve_id PK
        float cvss_v3_score
        float epss_score
        bool is_known_exploited
    }
    VULNERABILITY {
        string id PK
        string org_id FK
        string asset_id FK
        string cve_id FK
        string scan_import_id FK
        string scanner_severity
        string status
    }
    RISK_SCORE {
        string id PK
        string vulnerability_id FK
        float composite_score
        string score_version
        datetime calculated_at
    }
    REMEDIATION_TASK {
        string id PK
        string vulnerability_id FK
        string assigned_to_id FK
        string status
        string priority
        int sla_days
    }
    SCAN_IMPORT {
        string id PK
        string org_id FK
        string scanner_type
        string status
    }
```

## Key design decisions this diagram makes visible

1. **CVE is the only global (non-tenant-scoped) table.** Every other table has an
   `org_id` foreign key enforcing tenant isolation at the schema level, not just in
   application code — a query that forgets to filter by `org_id` gets caught by
   review/tests rather than silently leaking cross-tenant data.
2. **RiskScore is 1-to-many against Vulnerability**, not 1-to-1. This is what makes
   historical trend charts possible: every recalculation (daily EPSS refresh, KEV
   status change, asset criticality edit) inserts a new row instead of overwriting.
3. **Vulnerability.cve_id is nullable.** Config-only findings (no CVE) still flow
   through the same pipeline, they just don't get CVSS/EPSS/KEV enrichment.
