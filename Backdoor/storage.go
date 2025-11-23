package main

import (
	"sync"
	"time"
)

type MemoryStorage struct {
	mu            sync.RWMutex
	logs          []FirewallLog
	requestCount  int64
	blockedCount  int64
	rateLimits    map[string]*RateLimitData
}

type RateLimitData struct {
	Requests     []time.Time
	BlockedUntil *time.Time
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		logs:       make([]FirewallLog, 0),
		rateLimits: make(map[string]*RateLimitData),
	}
}

func (s *MemoryStorage) SaveLog(log FirewallLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = append(s.logs, log)
}

func (s *MemoryStorage) GetLogs(limit int) []FirewallLog {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	start := len(s.logs) - limit
	if start < 0 {
		start = 0
	}
	
	result := make([]FirewallLog, len(s.logs)-start)
	copy(result, s.logs[start:])
	return result
}

func (s *MemoryStorage) IncrementRequest() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requestCount++
}

func (s *MemoryStorage) IncrementBlocked() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockedCount++
}

func (s *MemoryStorage) GetStats() *ThreatStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	stats := &ThreatStats{
		TotalRequests:   s.requestCount,
		BlockedRequests: s.blockedCount,
		ThreatsByType:   make(map[ThreatType]int64),
		ThreatsByIP:     make(map[string]int64),
		BlockedIPs:      0,
	}
	
	ipCount := make(map[string]int64)
	for _, log := range s.logs {
		stats.TotalThreats++
		stats.ThreatsByType[log.Type]++
		ipCount[log.IP]++
	}
	stats.ThreatsByIP = ipCount
	
	return stats
}

func (s *MemoryStorage) GetRateLimitData(key string) *RateLimitData {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rateLimits[key]
}

func (s *MemoryStorage) SaveRateLimitData(key string, data *RateLimitData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rateLimits[key] = data
}