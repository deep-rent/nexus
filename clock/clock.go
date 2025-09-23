package clock

import "time"

type Clock func() time.Time

func SystemClock() Clock { return time.Now }

func FrozenClock(t time.Time) Clock { return func() time.Time { return t } }
