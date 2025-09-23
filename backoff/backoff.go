package backoff

import (
	"math"
	"math/rand/v2"
	"sync/atomic"
	"time"
)

const (
	// DefaultMinDelay is the default minimum time between consecutive retries.
	DefaultMinDelay = 1 * time.Second
	// DefaultMaxDelay is the default maximum time between consecutive retries.
	DefaultMaxDelay = 1 * time.Minute
	// DefaultGrowthFactor is the default growth factor in exponential backoff.
	DefaultGrowthFactor = 2.0
	// DefaultJitterAmount is the default amount of jitter applied.
	DefaultJitterAmount = 0.3
)

// Strategy defines the contract for a backoff algorithm.
// Implementations of this interface are expected to be safe for concurrent use.
type Strategy interface {
	// Next returns the backoff duration for the upcoming retry attempt.
	// This method is stateful and returns incrementally larger durations based
	// on the number of times it has been called since the last call to Done.
	// The returned duration is bounded by MinDelay() and MaxDelay().
	Next() time.Duration
	// Done resets the strategy's internal state, such as its attempt counter.
	// This must be called after the retried operation succeeds or is abandoned.
	Done()
	// MinDelay returns the lower bound for the backoff duration returned by Next.
	MinDelay() time.Duration
	// MaxDelay returns the upper bound for the backoff duration returned by Next.
	MaxDelay() time.Duration
}

type constant struct {
	delay time.Duration
}

// Constant produces a Strategy that always yields the same delay duration.
// If the provided delay is negative, it is treated as zero (meaning no delay).
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

// Rand serves as a minimal facade over rand.Rand to ease mocking.
type Rand interface {
	// Float64 generates a pseudo-random number in [0.0, 1.0).
	Float64() float64
}

var _ Rand = (*rand.Rand)(nil)

type jitter struct {
	strategy Strategy
	amount   float64
	r        Rand
}

func (j *jitter) Next() time.Duration {
	f := j.r.Float64()
	return time.Duration(float64(j.strategy.Next()) * (1 - f*j.amount))
}

func (j *jitter) Done() {
	j.strategy.Done()
}

func (j *jitter) MinDelay() time.Duration {
	return time.Duration(float64(j.strategy.MinDelay()) * (1 - j.amount))
}

func (j *jitter) MaxDelay() time.Duration {
	return j.strategy.MaxDelay()
}

var _ Strategy = (*jitter)(nil)

type config struct {
	minDelay     time.Duration
	maxDelay     time.Duration
	growthFactor float64
	jitterAmount float64
	r            Rand
}

// Option customizes the behavior of a backoff Strategy.
type Option func(*config)

// WithMinDelay sets the minimum time between consecutive retries.
// It is capped at zero (meaning no delay) if a negative duration is provided.
// If equal to or greater than the maximum delay, the backoff delays remain
// constant at the maximum delay. If not customized, the DefaultMinDelay
// is used.
//
// When jitter is introduced, the minimum delay is effectively reduced
// proportional to the jitter amount. Thus, the strategy might return a delay
// shorter than the configured minimum delay, depending on the random output.
func WithMinDelay(d time.Duration) Option {
	return func(c *config) {
		c.minDelay = max(0, d)
	}
}

// WithMaxDelay sets the maximum time between consecutive retries.
// It is capped at zero (meaning no delay) if a negative duration is provided.
// If less than or equal to the minimum delay, the backoff delays remain
// constant at the maximum delay. If not customized, the DefaultMaxDelay
// is used.
func WithMaxDelay(d time.Duration) Option {
	return func(c *config) {
		c.maxDelay = max(0, d)
	}
}

// WithGrowthFactor determines the growth factor (multiplier) for exponential
// backoff. A factor equal to one results in linear backoff, where the minimum
// delay becomes the step size. Any factor less than one is treated as one.
// If not customized, the DefaultGrowthFactor is used.
func WithGrowthFactor(f float64) Option {
	return func(c *config) {
		c.growthFactor = f
	}
}

// WithJitterAmount specifies the amount of random jitter to apply to the
// backoff delays. It is expressed as a fraction of the delay, where 0 means no
// jitter and 1 means full jitter. The given number is capped between 0 and 1.
// If not customized, the DefaultJitterAmount is used.
//
// Jitter scatters the retry attempts in time, which aims to mitigate the
// thundering herd problem, where many clients retry simultaneously.
func WithJitterAmount(p float64) Option {
	return func(c *config) {
		c.jitterAmount = min(1, p)
	}
}

// WithRand sets the source of randomness for jittering. If not specified or
// nil, a default source will be seeded with the current system time.
func WithRand(r Rand) Option {
	return func(c *config) {
		if r != nil {
			c.r = r
		}
	}
}

// New creates a new backoff Strategy based on the provided options.
func New(opts ...Option) Strategy {
	c := config{
		minDelay:     DefaultMinDelay,
		maxDelay:     DefaultMaxDelay,
		growthFactor: DefaultGrowthFactor,
		jitterAmount: DefaultJitterAmount,
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

	s := &exponential{
		minDelay:     c.minDelay,
		maxDelay:     c.maxDelay,
		growthFactor: c.growthFactor,
	}

	if c.jitterAmount <= 0 {
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
		amount:   c.jitterAmount,
		r:        r,
	}
}
