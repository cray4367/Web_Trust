package main

import (
	"net/http"
	"regexp"
	"strings"
	"time"
)

type ThreatDetector struct {
	sqlPatterns []*regexp.Regexp
	xssPatterns []*regexp.Regexp
}

func NewThreatDetector() *ThreatDetector {
	return &ThreatDetector{
		sqlPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC|ALTER|CREATE|TRUNCATE)\b`),
			regexp.MustCompile(`(?i)\b(OR|AND)\s+['"]?\d+['"]?\s*[=<>]`),
			regexp.MustCompile(`(--|\/\*|\*\/|;)`),
		},
		xssPatterns: []*regexp.Regexp{
			regexp.MustCompile(`<script\b`),
			regexp.MustCompile(`(?i)javascript:`),
			regexp.MustCompile(`on\w+\s*=`),
			regexp.MustCompile(`<iframe`),
		},
	}
}

func (td *ThreatDetector) AnalyzeRequest(r *http.Request) *FirewallLog {
	// Check URL parameters
	for key, values := range r.URL.Query() {
		for _, value := range values {
			if threat := td.checkInput(value); threat != "" {
				return &FirewallLog{
					Type:      SuspiciousInput,
					IP:        getClientIP(r),
					UserAgent: r.UserAgent(),
					Endpoint:  r.URL.Path,
					Method:    r.Method,
					Action:    "BLOCKED",
					Timestamp: time.Now(),
					Details:   threat + " in parameter: " + key,
				}
			}
		}
	}
	
	return nil
}

func (td *ThreatDetector) checkInput(input string) string {
	for _, pattern := range td.sqlPatterns {
		if pattern.MatchString(input) {
			return "SQL injection attempt"
		}
	}
	
	for _, pattern := range td.xssPatterns {
		if pattern.MatchString(input) {
			return "XSS attempt"
		}
	}
	
	return ""
}

func getClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return forwarded
	}
	return strings.Split(r.RemoteAddr, ":")[0] // Remove port
}