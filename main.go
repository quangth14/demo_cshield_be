package main

import (
	"demo_cshield_be/hanlder"
	"demo_cshield_be/middewares"
	"demo_cshield_be/models"
	"encoding/hex"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// ==== Hằng số contract chữ ký ====
const (
	keyID = "k_local"
	// CSI_SECRET = hex của raw key bytes; hex-decode để lấy HMAC key.
	secretHex = "8e3bd70259f4a16c11bd4790e2357acf6418ab53de0972f12c864fba0d9763e8"
)

func newNonceStore() *models.NonceStore { return &models.NonceStore{M: make(map[string]time.Time)} }

func newDedupStore() *models.DedupStore { return &models.DedupStore{M: make(map[string]struct{})} }

func main() {
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		log.Fatalf("CSI_SECRET không phải hex hợp lệ: %v", err)
	}

	srv := &models.Server{
		Secrets: map[string][]byte{keyID: secret},
		Nonces:  newNonceStore(),
		Dedup:   newDedupStore(),
	}

	// sweeper dọn nonce hết hạn
	go func() {
		t := time.NewTicker(60 * time.Second)
		for range t.C {
			srv.Nonces.Sweep(time.Now())
		}
	}()

	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", func(c *gin.Context) {
		c.String(http.StatusOK, "ok\n")
	})
	r.POST("/v1/log_detection:batch", middewares.AuthMiddleware(srv), hanlder.HandleBatch)
	r.Run(":8080")
}
