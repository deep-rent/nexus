package backoff

import (
	"math"
	"sync/atomic"
	"time"
)

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

func (c *constant) Next() time.Duration     { return c.delay }
func (c *constant) Done()                   {}
func (c *constant) MinDelay() time.Duration { return c.delay }
func (c *constant) MaxDelay() time.Duration { return c.delay }

var _ Strategy = (*constant)(nil)

type linear struct {
	minDelay time.Duration
	maxDelay time.Duration
	attempts atomic.Int64
}

func (l *linear) Next() time.Duration {
	n := l.attempts.Add(1)
	d := l.minDelay * time.Duration(n)
	return max(l.minDelay, min(l.maxDelay, d))
}

func (l *linear) Done()                   { l.attempts.Store(0) }
func (l *linear) MinDelay() time.Duration { return l.minDelay }
func (l *linear) MaxDelay() time.Duration { return l.maxDelay }

var _ Strategy = (*linear)(nil)

type exponential struct {
	minDelay time.Duration
	maxDelay time.Duration
	growth   float64
	attempts atomic.Int64
}

func (e *exponential) Next() time.Duration {
	n := e.attempts.Add(1)
	d := time.Duration(float64(e.minDelay) * math.Pow(e.growth, float64(n)))
	return max(e.minDelay, min(e.maxDelay, d))
}

func (e *exponential) Done()                   { e.attempts.Store(0) }
func (e *exponential) MinDelay() time.Duration { return e.minDelay }
func (e *exponential) MaxDelay() time.Duration { return e.maxDelay }

var _ Strategy = (*exponential)(nil)

type Rand interface {
	Float64() float64
}

type jitter struct {
	strategy Strategy
	p        float64
	r        Rand
}

func (j *jitter) Next() time.Duration {
	f := j.r.Float64()
	return time.Duration(float64(j.strategy.Next()) * (1 - j.p*f))
}

func (j *jitter) Done() {
	j.strategy.Done()
}

func (j *jitter) MinDelay() time.Duration {
	return time.Duration(float64(j.strategy.MinDelay()) * j.p)
}

func (j *jitter) MaxDelay() time.Duration {
	return j.strategy.MaxDelay()
}

var _ Strategy = (*jitter)(nil)
