export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type RiskLevel = "low" | "medium" | "high" | "critical";
export type PlainObject = Record<string, unknown>;

export interface Evidence {
  id: string;
  severity: Severity;
  confidence: number;
  title: string;
  explanation: string;
  details: PlainObject;
}

export interface RedirectHop {
  url: string;
  host: string;
  status_code: number | null;
  location: string | null;
  blocked_reason: string | null;
}

export interface ParsedUrl {
  scheme: string;
  hostname: string;
  ascii_hostname: string;
  port: number | null;
  path: string;
  query: string;
  fragment: string;
  username_present: boolean;
}

export interface AnalysisResult {
  submitted_url: string;
  parsed: ParsedUrl;
  risk_level: RiskLevel;
  score: number;
  summary: string;
  recommendation: string;
  evidence: Evidence[];
  redirects: RedirectHop[];
  dns_addresses: string[];
  tls: PlainObject | null;
  intelligence: PlainObject[];
  privacy_notice: string;
}

export interface QrResponse {
  payload_type: string;
  extracted_content: string;
  analysis: AnalysisResult | null;
}
