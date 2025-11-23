package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type WebTrustFirewall struct {
	store      *MemoryStorage
	detector   *ThreatDetector
	rateLimiter *RateLimiter
}

func NewWebTrustFirewall(store *MemoryStorage) *WebTrustFirewall {
	return &WebTrustFirewall{
		store:      store,
		detector:   NewThreatDetector(),
		rateLimiter: NewRateLimiter(store),
	}
}

func (fw *WebTrustFirewall) AnalyzeRequest(r *http.Request) *FirewallLog {
	if threat := fw.detector.AnalyzeRequest(r); threat != nil {
		return threat
	}
	
	clientIP := getClientIP(r)
	if blocked := fw.rateLimiter.CheckRateLimit(clientIP, r.URL.Path); blocked != nil {
		return &FirewallLog{
			Type:      RateLimit,
			IP:        clientIP,
			UserAgent: r.UserAgent(),
			Endpoint:  r.URL.Path,
			Method:    r.Method,
			Action:    "BLOCKED",
			Timestamp: time.Now(),
			Details:   "Rate limit exceeded: " + blocked.Reason,
		}
	}
	
	return nil
}

func (fw *WebTrustFirewall) LogRequest(log *FirewallLog) {
	fw.store.SaveLog(*log)
	if log.Action == "BLOCKED" {
		fw.store.IncrementBlocked()
	}
	fw.store.IncrementRequest()
}

func (fw *WebTrustFirewall) GetStatsHandler(c *gin.Context) {
	stats := fw.store.GetStats()
	c.JSON(http.StatusOK, stats)
}

func (fw *WebTrustFirewall) GetLogsHandler(c *gin.Context) {
	logs := fw.store.GetLogs(50)
	c.JSON(http.StatusOK, logs)
}

// Rate Limiter
type RateLimiter struct {
	store *MemoryStorage
}

type RateLimitResult struct {
	Allowed bool
	Reason  string
}

func NewRateLimiter(store *MemoryStorage) *RateLimiter {
	return &RateLimiter{
		store: store,
	}
}

func (rl *RateLimiter) CheckRateLimit(ip, endpoint string) *RateLimitResult {
	key := ip + ":" + endpoint
	now := time.Now()
	
	data := rl.store.GetRateLimitData(key)
	if data == nil {
		data = &RateLimitData{
			Requests: make([]time.Time, 0),
		}
	}
	
	// Clean old requests (last minute)
	var recentRequests []time.Time
	for _, reqTime := range data.Requests {
		if now.Sub(reqTime) < time.Minute {
			recentRequests = append(recentRequests, reqTime)
		}
	}
	
	// Check if blocked
	if data.BlockedUntil != nil && now.Before(*data.BlockedUntil) {
		return &RateLimitResult{
			Allowed: false,
			Reason:  "IP temporarily blocked",
		}
	}
	
	// Check minute limit (60 requests per minute)
	if len(recentRequests) >= 60 {
		blockUntil := now.Add(15 * time.Minute)
		data.BlockedUntil = &blockUntil
		rl.store.SaveRateLimitData(key, data)
		
		return &RateLimitResult{
			Allowed: false,
			Reason:  "Rate limit exceeded (60/min)",
		}
	}
	
	// Add current request
	recentRequests = append(recentRequests, now)
	data.Requests = recentRequests
	rl.store.SaveRateLimitData(key, data)
	
	return nil
}