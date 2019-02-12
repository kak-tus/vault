package contextutil

import (
	"context"
	"time"
)

func BackoffOrQuit(ctx context.Context, backoff time.Duration) {
	select {
	case <-time.After(backoff):
	case <-ctx.Done():
	}
}
