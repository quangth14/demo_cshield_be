package hanlder

import (
	"encoding/json"
	"log"
	"net/http"

	"demo_cshield_be/models"

	"github.com/gin-gonic/gin"
)

// handleBatch: chỉ chạy sau khi authMiddleware pass -> decode + dedup + store.
func HandleBatch(c *gin.Context) {
	var req models.ReqBody

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var rawJson, _ = json.MarshalIndent(req, "", "  ")

	log.Printf("Log-detection:\n%s", string(rawJson))

	c.JSON(http.StatusOK, gin.H{"result": req, "raw_json": rawJson})
}
