/**
 * API TypeScript interfaces — mirrors backend schemas exactly.
 *
 * Organized by: Auth, URL Analysis, Health
 */

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface UserMeResponse {
  id: string;
  email: string;
  created_at: string;
  mfa_enabled: boolean;
  last_login_at: string | null;
}

export interface RegisterRequest {
  email: string;
  password: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RefreshRequest {
  refresh_token: string;
}

export interface LogoutRequest {
  refresh_token: string;
}

// ---------------------------------------------------------------------------
// URL Analysis — Enums
// ---------------------------------------------------------------------------

export type RiskClassification = 'LOW_RISK' | 'MEDIUM_RISK' | 'HIGH_RISK' | 'CRITICAL';
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ReasonCode =
  | 'HTTP_NOT_HTTPS'
  | 'IP_HOSTNAME'
  | 'PUNYCODE_DOMAIN'
  | 'EXCESSIVE_SUBDOMAINS'
  | 'SUSPICIOUS_TLD'
  | 'SUSPICIOUS_KEYWORD'
  | 'CREDENTIAL_PATH'
  | 'USERINFO_PRESENT'
  | 'NON_STANDARD_PORT'
  | 'EXCESSIVE_URL_LENGTH'
  | 'HIGH_ENCODING_RATIO'
  | 'SUSPICIOUS_COMBINATION'
  | 'TI_REPUTATION';

export type ThreatIntelStatus = 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';

// ---------------------------------------------------------------------------
// URL Analysis — Schemas
// ---------------------------------------------------------------------------

export interface RiskReason {
  code: ReasonCode;
  severity: Severity;
  message: string;
}

export interface ThreatIntelSummary {
  provider: string;
  status: ThreatIntelStatus;
  confidence: number | null;
  reason: string | null;
  cached: boolean;
  provider_error: boolean;
  checked_at: string;
}

export interface URLScanRequest {
  url: string;
}

export interface URLScanResponse {
  id: string;
  url: string;
  risk_score: number;
  classification: RiskClassification;
  reasons: RiskReason[];
  features: Record<string, unknown>;
  analyzer_version: string;
  threat_intelligence: ThreatIntelSummary | null;
  created_at: string;
}

export interface URLScanSummary {
  id: string;
  url: string;
  risk_score: number;
  classification: RiskClassification;
  analyzer_version: string;
  created_at: string;
}

export interface URLScanHistoryResponse {
  items: URLScanSummary[];
  total: number;
  limit: number;
  offset: number;
}

// ---------------------------------------------------------------------------
// M7 Multi-Vector Analysis Types & Schemas
// ---------------------------------------------------------------------------

export type ThreatCategory =
  | 'credential_theft'
  | 'social_engineering'
  | 'financial_lure'
  | 'malicious_attachment'
  | 'structural_anomaly'
  | 'reputation'
  | 'evasion'
  | 'executable_content'
  | 'archive_risk';

export interface ExplainableReason {
  category: ThreatCategory;
  severity: Severity;
  title: string;
  explanation: string;
  score_contribution: number;
  rule_id?: string | null;
}

export interface MessageScanRequest {
  message?: string;
  body?: string;
  subject?: string | null;
  sender?: string | null;
}


export interface ExtractedURLAnalysis {
  url: string;
  risk_score: number;
  classification: RiskClassification;
}

export interface MessageScanResponse {
  id: string;
  message_hash: string;
  risk_score: number;
  classification: RiskClassification;
  confidence: number;
  reasons: ExplainableReason[];
  features: Record<string, unknown>;
  extracted_urls: ExtractedURLAnalysis[];
  analyzer_version: string;
  created_at: string;
}

export interface MessageScanSummary {
  id: string;
  risk_score: number;
  classification: RiskClassification;
  confidence: number;
  summary: string;
  urls_count: number;
  analyzer_version: string;
  created_at: string;
}

export interface MessageScanHistoryResponse {
  items: MessageScanSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface FileScanResponse {
  id: string;
  file_hash: string;
  filename: string;
  file_size: number;
  detected_type: string;
  declared_mime: string;
  risk_score: number;
  classification: RiskClassification;
  confidence: number;
  reasons: ExplainableReason[];
  features: Record<string, unknown>;
  analyzer_version: string;
  created_at: string;
}

export interface FileScanSummary {
  id: string;
  file_hash: string;
  filename: string;
  file_size: number;
  detected_type: string;
  risk_score: number;
  classification: RiskClassification;
  confidence: number;
  analyzer_version: string;
  created_at: string;
}


export interface FileScanHistoryResponse {
  items: FileScanSummary[];
  total: number;
  limit: number;
  offset: number;
}

// ---------------------------------------------------------------------------
// Security Incidents & Attack Chains (M8)
// ---------------------------------------------------------------------------

export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';

export type AttackStage =
  | 'RECONNAISSANCE'
  | 'INITIAL_ACCESS'
  | 'CREDENTIAL_HARVESTING'
  | 'MALICIOUS_DELIVERY'
  | 'EVASION_EXECUTION'
  | 'SOCIAL_ENGINEERING'
  | 'MULTI_VECTOR_CAMPAIGN';

export interface IncidentIndicator {
  indicator_type: string;
  indicator_value: string;
  first_seen: string;
  last_seen: string;
  frequency: number;
}

export interface IncidentEventSummary {
  id: string;
  incident_id: string;
  event_type: 'URL_SCAN' | 'MESSAGE_SCAN' | 'FILE_SCAN';
  event_ref_id: string;
  risk_score: number;
  risk_contribution: number;
  correlation_reason: string;
  created_at: string;
}

export interface IncidentSummary {
  id: string;
  title: string;
  status: IncidentStatus;
  severity: RiskClassification;
  risk_score: number;
  threat_score?: number;
  confidence: number;
  attack_stage: AttackStage;
  event_count: number;
  first_seen?: string;
  last_seen?: string;
  created_at: string;
  updated_at?: string;
  resolved_at?: string | null;
}

export interface IncidentDetail {
  id: string;
  title: string;
  status: IncidentStatus;
  severity: RiskClassification;
  risk_score: number;
  threat_score?: number;
  confidence: number;
  attack_stage: AttackStage;
  indicators: IncidentIndicator[];
  explainable_reasons: ExplainableReason[];
  behavioral_summary: Record<string, unknown> | null;
  event_count: number;
  first_seen?: string;
  last_seen?: string;
  created_at: string;
  updated_at?: string;
  resolved_at?: string | null;
  events: IncidentEventSummary[];
}

export interface IncidentTimelineEvent {
  id: string;
  event_type: string;
  event_id: string;
  relationship_reason: string;
  created_at: string;
  summary?: string | null;
  risk_score?: number | null;
  classification?: string | null;
}

export interface IncidentTimelineResponse {
  incident_id: string;
  title: string;
  severity: string;
  status: string;
  events: IncidentTimelineEvent[];
}

export interface IncidentListResponse {
  items: IncidentSummary[];
  total: number;
  limit: number;
  offset: number;
  status_counts: Record<string, number>;
}

export interface IncidentStatusUpdateRequest {
  status: IncidentStatus;
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

export interface LivenessResponse {
  status: string;
}

export interface ReadinessResponse {
  status: string;
  checks: Record<string, string>;
}

// ---------------------------------------------------------------------------
// API Error
// ---------------------------------------------------------------------------

export interface APIError {
  detail: string | Record<string, unknown>[];
  correlation_id?: string;
}

