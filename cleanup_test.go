package mcpauth_test

import (
	"context"
	"testing"
	"time"

	mcpauth "github.com/kabili207/go-mcp-auth"
)

type countingCleaner chan struct{}

func (c countingCleaner) Cleanup(ctx context.Context) error {
	c <- struct{}{}
	return nil
}

func TestRunCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := make(countingCleaner)
	done := make(chan struct{})
	go func() {
		mcpauth.RunCleanup(ctx, calls, time.Millisecond)
		close(done)
	}()

	// Once at start, then again on the ticker.
	for range 2 {
		select {
		case <-calls:
		case <-time.After(time.Second):
			t.Fatal("Cleanup was not called")
		}
	}

	cancel()
	for {
		select {
		case <-calls:
		case <-done:
			return
		case <-time.After(time.Second):
			t.Fatal("RunCleanup did not stop when its context ended")
		}
	}
}
