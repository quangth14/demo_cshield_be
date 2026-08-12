package hanlder

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"demo_cshield_be/models"
)

// handleBatch: chỉ chạy sau khi authMiddleware pass -> decode + dedup + store.
func HandleBatch(c *gin.Context) {
	var req models.ReqBody

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var rawJson, _ = json.MarshalIndent(req, "", "  ")

	println(string(rawJson))

	c.JSON(http.StatusOK, gin.H{"result": req, "raw_json": rawJson})
}
