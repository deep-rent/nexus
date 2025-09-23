package backoff

import "time"

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
