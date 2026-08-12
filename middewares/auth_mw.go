package middewares

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"demo_cshield_be/models"
	"github.com/gin-gonic/gin"
)

// ==== Hằng số contract chữ ký ====
const (
	sigLabel   = "CSI-LOGSIG-v1"           // domain-separation label (dòng đầu string-to-sign, KHÔNG có dấu ngoặc kép)
	sigMethod  = "POST"                    // HTTP method dùng để ký
	sigPath    = "/v1/log_detection:batch" // path dùng để ký
	skewMs     = int64(300_000)            // timestamp skew tối đa: 300s
	maxBodyLen = 8 << 20                   // 8MB giới hạn body
)

// authMiddleware: xác thực HMAC theo đúng thứ tự contract. Chỉ khi pass mới
// truyền raw body đã xác thực xuống handler qua Context.
func AuthMiddleware(s *models.Server) gin.HandlerFunc {
	return func(c *gin.Context) {
		now := time.Now()

		// --- 1) Đọc raw body (dùng để tính SHA256, ký trên đúng bytes trên đường truyền) ---
		raw, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBodyLen))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "read_error"})
			return
		}
		// Restore body để handler phía sau (ShouldBindJSON) có thể đọc lại
		c.Request.Body = io.NopCloser(bytes.NewReader(raw))

		// --- 2) VERIFY HMAC (đúng thứ tự contract) ---
		// 2a) đủ header?
		kid := c.GetHeader("CMC-CS-Key-Id")
		tsStr := c.GetHeader("CMC-CS-Timestamp")
		nonce := c.GetHeader("CMC-CS-Nonce")
		sig := c.GetHeader("CMC-CS-Signature")
		if kid == "" || tsStr == "" || nonce == "" || sig == "" {
			denyAuth(c, "missing_header", kid)
			return
		}
		// 2b) timestamp skew ≤ 300_000ms
		tsMs, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			denyAuth(c, "skew", kid)
			return
		}
		nowMs := now.UnixMilli()
		if d := nowMs - tsMs; d > skewMs || d < -skewMs {
			denyAuth(c, "skew", kid)
			return
		}
		// 2c) nonce chống replay (kid,nonce) TTL 300s
		nonceKey := kid + ":" + nonce
		if s.Nonces.Seen(nonceKey, now) {
			denyAuth(c, "replay", kid)
			return
		}
		// 2d) tra secret theo key_id
		secret, ok := s.Secrets[kid]
		if !ok {
			denyAuth(c, "unknown_key", kid)
			return
		}
		// 2e) so sánh constant-time
		bodyHashHex := hex.EncodeToString(sha256Sum(raw))
		sts := sigLabel + "\n" + sigMethod + "\n" + sigPath + "\n" + tsStr + "\n" + nonce + "\n" + bodyHashHex
		expectedMAC := hmacSHA256(secret, []byte(sts))
		providedMAC, err := base64.StdEncoding.DecodeString(sig)
		if err != nil || !hmac.Equal(expectedMAC, providedMAC) {
			denyAuth(c, "bad_sig", kid)
			return
		}
		// signature hợp lệ -> tiêu thụ nonce (chống replay các request đã xác thực)
		s.Nonces.Add(nonceKey, now)
		c.Next()
	}
}

// denyAuth: log + trả 401 cho lỗi xác thực (để theo dõi request đến).
func denyAuth(c *gin.Context, reason, kid string) {
	log.Printf("REQ 401 auth_fail reason=%s kid=%q from=%s", reason, kid, c.Request.RemoteAddr)
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": reason})
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func Getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
