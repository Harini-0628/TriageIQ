// Mirrors the backend Pydantic response schemas exactly (app/schemas/*.py).
// Kept as one file for a project this size — worth splitting per-domain
// once the app grows past a handful of pages.

export interface User {
  id: string;
  org_id: string;
  email: string;
  full_name: string;
  role: "admin" | "analyst" | "viewer";
  is_active: boolean;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface DashboardSummary {
  total_assets: number;
  total_open_vulnerabilities: number;
  vulnerabilities_by_severity: Record<string, number>;
  vulnerabilities_by_status: Record<string, number>;
  average_risk_score: number | null;
  known_exploited_open_count: number;
  top_risky_assets: {
    hostname: string;
    criticality: string;
    open_vulnerability_count: number;
    highest_risk_score: number | null;
  }[];
  sla_compliance: {
    total_tasks: number;
    overdue_tasks: number;
    compliance_rate: number;
  };
}

export interface RankedVulnerability {
  vulnerability_id: string;
  title: string;
  cve_id: string | null;
  asset_hostname: string;
  asset_criticality: string;
  status: string;
  composite_score: number;
  cvss_component: number;
  epss_component: number;
  kev_component: number;
  asset_criticality_component: number;
  exposure_component: number;
  age_component: number;
  calculated_at: string;
}

export interface Asset {
  id: string;
  hostname: string;
  ip_address: string | null;
  asset_type: string;
  criticality: "critical" | "high" | "medium" | "low";
  environment: string;
  internet_facing: boolean;
  owner: string | null;
  open_vulnerability_count: number;
  created_at: string;
}

export interface VulnerabilityListItem {
  id: string;
  asset_hostname: string;
  cve_id: string | null;
  title: string;
  scanner_severity: string;
  status: string;
  latest_risk_score: number | null;
  last_detected_at: string;
}

export interface Notification {
  id: string;
  type: string;
  title: string;
  message: string;
  is_read: boolean;
  created_at: string;
}
