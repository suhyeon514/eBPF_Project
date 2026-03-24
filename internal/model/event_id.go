package model

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

func NewEventID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UTC().UnixNano())
	}
	return fmt.Sprintf("%d-%s",
		time.Now().UTC().UnixNano(),
		hex.EncodeToString(b[:]),
	)
}
