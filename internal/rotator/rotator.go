package rotator

import "sync/atomic"

type Rotator[E any] struct {
	items []E
	index atomic.Uint64
}

func New[E any](items []E) *Rotator[E] {
	return &Rotator[E]{items: items}
}

func (r *Rotator[E]) Next() E {
	idx := r.index.Add(1)
	return r.items[(idx-1)%uint64(len(r.items))]
}
