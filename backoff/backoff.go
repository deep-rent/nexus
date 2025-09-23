package backoff

import (
	"sync/atomic"
	"time"
)

type config struct {
	minDelay time.Duration
	maxDelay time.Duration
}

type linearConfig struct {
	config
	step time.Duration
}

type Strategy interface {
	Next() time.Duration
	Done()
	MinDelay() time.Duration
	MaxDelay() time.Duration
}

type constant struct {
	delay time.Duration
}

func Constant(delay time.Duration) Strategy {
	return &constant{delay: max(0, delay)}
}

func (b *constant) Next() time.Duration     { return b.delay }
func (b *constant) Done()                   {}
func (b *constant) MinDelay() time.Duration { return b.delay }
func (b *constant) MaxDelay() time.Duration { return b.delay }

var _ Strategy = (*constant)(nil)

type linear struct {
	minDelay time.Duration
	maxDelay time.Duration
	step     time.Duration
	attempts atomic.Int64
}

func (b *linear) Next() time.Duration {
	n := b.attempts.Add(1) - 1
	d := b.minDelay + (time.Duration(n) * b.step)

	return min(b.maxDelay, d)
}

func (b *linear) Done()                   { b.attempts.Store(0) }
func (b *linear) MinDelay() time.Duration { return b.minDelay }
func (b *linear) MaxDelay() time.Duration { return b.maxDelay }

var _ Strategy = (*linear)(nil)
