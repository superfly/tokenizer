package flysrc

import (
	"context"
)

type contextKey string

const (
	contextKeyFlySrc = contextKey("fly-src")
)

func WithFlySrc(ctx context.Context, fsrc *Parsed) context.Context {
	return context.WithValue(ctx, contextKeyFlySrc, fsrc)
}

func FlySrcFromContext(ctx context.Context) *Parsed {
	fsrc, _ := ctx.Value(contextKeyFlySrc).(*Parsed)
	return fsrc
}
