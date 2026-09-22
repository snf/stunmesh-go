package stun

import (
	"context"
	"errors"
	"time"
)

const StunTimeout = 5 * time.Second

func defaultClientFactory(context.Context, string, uint16, string, int, []string, bool) (StunClient, error) {
	return nil, errors.New("STUN requires the shared UDP proxy transport")
}
