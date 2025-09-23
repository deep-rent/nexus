package backoff

import (
	"math"
	"math/rand/v2"
	"sync/atomic"
	"time"
)

const (
	DefaultMinDelay     = 1 * time.Second
	DefaultMaxDelay     = 1 * time.Minute
	DefaultGrowthFactor = 2.0
	DefaultJitter       = 0.5
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
	minDelay     time.Duration
	maxDelay     time.Duration
	growthFactor float64
	attempts     atomic.Int64
}

func (e *exponential) Next() time.Duration {
	n := e.attempts.Add(1)
	d := time.Duration(float64(e.minDelay) * math.Pow(e.growthFactor, float64(n)))
	return max(e.minDelay, min(e.maxDelay, d))
}

func (e *exponential) Done()                   { e.attempts.Store(0) }
func (e *exponential) MinDelay() time.Duration { return e.minDelay }
func (e *exponential) MaxDelay() time.Duration { return e.maxDelay }

var _ Strategy = (*exponential)(nil)

type config struct {
	minDelay     time.Duration
	maxDelay     time.Duration
	growthFactor float64
}

type Option func(*config)

func WithMinDelay(d time.Duration) Option {
	return func(c *config) {
		c.minDelay = max(0, d)
	}
}

func WithMaxDelay(d time.Duration) Option {
	return func(c *config) {
		c.maxDelay = max(0, d)
	}
}

func WithGrowthFactor(f float64) Option {
	return func(c *config) {
		c.growthFactor = f
	}
}

func Exponential(opts ...Option) Strategy {
	c := config{
		minDelay:     DefaultMinDelay,
		maxDelay:     DefaultMaxDelay,
		growthFactor: DefaultGrowthFactor,
	}
	for _, opt := range opts {
		opt(&c)
	}

	if c.minDelay >= c.maxDelay {
		return &constant{
			delay: c.maxDelay,
		}
	}

	if c.growthFactor <= 1 {
		return &linear{
			minDelay: c.minDelay,
			maxDelay: c.maxDelay,
		}
	}

	return &exponential{
		minDelay:     c.minDelay,
		maxDelay:     c.maxDelay,
		growthFactor: c.growthFactor,
	}
}

type Rand interface {
	Float64() float64
}

var _ Rand = (*rand.Rand)(nil)

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
	return time.Duration(float64(j.strategy.MinDelay()) * (1 - j.p))
}

func (j *jitter) MaxDelay() time.Duration {
	return j.strategy.MaxDelay()
}

var _ Strategy = (*jitter)(nil)

func Jitter(s Strategy, opts ...JitterOption) Strategy {
	c := jitterConfig{
		p: DefaultJitter,
		r: nil,
	}
	for _, opt := range opts {
		opt(&c)
	}
	p := c.p
	if p == 0 {
		return s
	}
	r := c.r
	if r == nil {
		s1 := uint64(time.Now().UnixNano())
		s2 := s1 + 1
		r = rand.New(rand.NewPCG(s1, s2))
	}
	return &jitter{
		strategy: s,
		p:        p,
		r:        r,
	}
}

type jitterConfig struct {
	p float64
	r Rand
}

type JitterOption func(*jitterConfig)

func WithPercentage(p float64) JitterOption {
	return func(c *jitterConfig) {
		c.p = max(0, min(1, p))
	}
}

func WithRand(r Rand) JitterOption {
	return func(c *jitterConfig) {
		if r != nil {
			c.r = r
		}
	}
}
