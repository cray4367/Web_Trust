package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	store := NewMemoryStorage()
	fw := NewWebTrustFirewall(store)
	
	router := gin.Default()
	
	// CORS middleware for React app on port 5173
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "http://localhost:5173")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		
		c.Next()
	})
	
	// Firewall middleware
	router.Use(func(c *gin.Context) {
		threat := fw.AnalyzeRequest(c.Request)
		
		if threat != nil {
			fw.LogRequest(threat)
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Request blocked by Web Trust Analyzer",
				"reason":  string(threat.Type),
				"details": threat.Details,
				"allowed": false,
			})
			c.Abort()
			return
		}
		
		c.Next()
	})
	
	// API routes
	api := router.Group("/api")
	{
		api.POST("/login", loginHandler)
		api.GET("/search", searchHandler)
		api.GET("/firewall/stats", fw.GetStatsHandler)
		api.GET("/firewall/logs", fw.GetLogsHandler)
	}
	
	log.Println("🚀 Web Trust Analyzer starting on :8080")
	log.Println("📊 React Frontend: http://localhost:5173")
	log.Println("🔧 Go Backend API: http://localhost:8080")
	log.Fatal(router.Run(":8080"))
}

func loginHandler(c *gin.Context) {
	var loginReq struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	
	if err := c.BindJSON(&loginReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request", "allowed": true})
		return
	}
	
	if loginReq.Username == "admin" && loginReq.Password == "password" {
		c.JSON(http.StatusOK, gin.H{
			"message": "Login successful",
			"user": "admin",
			"allowed": true,
		})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid credentials", 
			"allowed": true,
		})
	}
}

func searchHandler(c *gin.Context) {
	query := c.Query("q")
	c.JSON(http.StatusOK, gin.H{
		"results": []string{"Result 1: " + query, "Result 2: " + query},
		"query": query,
		"allowed": true,
	})
}