package backoff

import (
	"sync/atomic"
	"time"
)

const (
	DefaultMinDelay = 1 * time.Second
	DefaultMaxDelay = 5 * time.Minute
	DefaultStep     = 1 * time.Second
	DefaultFactor   = 2.0
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
	step     time.Duration
	attempts atomic.Int64
}

func Linear(opts ...Option) Strategy {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.minDelay >= cfg.maxDelay {
		return Constant(cfg.minDelay)
	}
	return &linear{
		minDelay: cfg.minDelay,
		maxDelay: cfg.maxDelay,
		step:     cfg.step,
	}
}

func (l *linear) Next() time.Duration {
	n := l.attempts.Add(1) - 1
	d := l.minDelay + (time.Duration(n) * l.step)
	return max(l.minDelay, min(d, l.maxDelay))
}

func (l *linear) Done()                   { l.attempts.Store(0) }
func (l *linear) MinDelay() time.Duration { return l.minDelay }
func (l *linear) MaxDelay() time.Duration { return l.maxDelay }

var _ Strategy = (*linear)(nil)

type exponential struct {
	minDelay time.Duration
	maxDelay time.Duration
	factor   float64
	attempts atomic.Int64
}

func Exponential(opts ...Option) Strategy {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.minDelay >= cfg.maxDelay {
		return Constant(cfg.minDelay)
	}
	return &exponential{
		minDelay: cfg.minDelay,
		maxDelay: cfg.maxDelay,
		factor:   cfg.factor,
	}
}

func (e *exponential) Next() time.Duration     { return 0 }
func (e *exponential) Done()                   { e.attempts.Store(0) }
func (e *exponential) MinDelay() time.Duration { return e.minDelay }
func (e *exponential) MaxDelay() time.Duration { return e.maxDelay }

var _ Strategy = (*exponential)(nil)

type Option func(*config)

type config struct {
	minDelay time.Duration
	maxDelay time.Duration
	step     time.Duration
	factor   float64
}

func defaultConfig() config {
	return config{
		minDelay: DefaultMinDelay,
		maxDelay: DefaultMaxDelay,
		step:     DefaultStep,
		factor:   DefaultFactor,
	}
}

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

func WithStep(d time.Duration) Option {
	return func(c *config) {
		c.step = max(0, d)
	}
}

func WithFactor(f float64) Option {
	return func(c *config) {
		c.factor = max(1, f)
	}
}
