package main

import "time"

type ThreatType string

const (
	SQLInjection    ThreatType = "SQL_INJECTION"
	XSS             ThreatType = "XSS"
	RateLimit       ThreatType = "RATE_LIMIT_EXCEEDED"
	SuspiciousInput ThreatType = "SUSPICIOUS_INPUT"
)

type FirewallLog struct {
	ID        string    `json:"id"`
	Type      ThreatType `json:"type"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Endpoint  string    `json:"endpoint"`
	Method    string    `json:"method"`
	Action    string    `json:"action"`
	Timestamp time.Time `json:"timestamp"`
	Details   string    `json:"details"`
}

type ThreatStats struct {
	TotalRequests   int64                  `json:"total_requests"`
	BlockedRequests int64                  `json:"blocked_requests"`
	TotalThreats    int64                  `json:"total_threats"`
	BlockedIPs      int64                  `json:"blocked_ips"`
	ThreatsByType   map[ThreatType]int64   `json:"threats_by_type"`
	ThreatsByIP     map[string]int64       `json:"threats_by_ip"`
}