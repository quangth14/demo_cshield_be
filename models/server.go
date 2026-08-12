package models

import (
	"sync"
	"time"
)

type NonceStore struct {
	Mu sync.Mutex
	M  map[string]time.Time // "kid:nonce" -> thời điểm hết hạn
}

// seen: nonce đã tồn tại và còn hạn?
func (s *NonceStore) Seen(key string, now time.Time) bool {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	exp, ok := s.M[key]
	if !ok {
		return false
	}
	if now.After(exp) {
		delete(s.M, key)
		return false
	}
	return true
}

// add: đánh dấu nonce đã tiêu thụ (gọi sau khi signature hợp lệ)
func (s *NonceStore) Add(key string, now time.Time) {
	s.Mu.Lock()
	s.M[key] = now.Add(300 * time.Second)
	s.Mu.Unlock()
}

func (s *NonceStore) Sweep(now time.Time) {
	s.Mu.Lock()
	for k, exp := range s.M {
		if now.After(exp) {
			delete(s.M, k)
		}
	}
	s.Mu.Unlock()
}

type DedupStore struct {
	Mu sync.Mutex
	M  map[string]struct{} // event_id đã nhận
}

// checkAndAdd: true nếu là event mới (đã thêm), false nếu trùng.
func (s *DedupStore) CheckAndAdd(eventID string) bool {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if _, ok := s.M[eventID]; ok {
		return false
	}
	s.M[eventID] = struct{}{}
	return true
}

type Server struct {
	Secrets map[string][]byte // key_id -> HMAC key (raw bytes, đã hex-decode)
	Nonces  *NonceStore
	Dedup   *DedupStore
}


