package main

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"time"
)

func newToken() string {
	return randHexString(32)
}

func newUUIDLikeID() string {
	s := randHexString(32)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

func newShortID() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		fallback := time.Now().UnixNano()
		for i := range b {
			b[i] = chars[fallback%62]
			fallback /= 62
			if fallback == 0 {
				fallback = time.Now().UnixNano() + int64(i)
			}
		}
		return string(b[:])
	}
	for i := range b {
		b[i] = chars[int(b[i])%62]
	}
	return string(b[:])
}

func randHexString(n int) string {
	buf := make([]byte, (n+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(buf)[:n]
}
