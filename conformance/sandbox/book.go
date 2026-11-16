package sandbox

import (
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
)

// instances numbers the instances of every sandbox of the process, so that
// no two have the same names.
var instances atomic.Int64

// book is a sandbox's bookkeeping of its instances: which slot of the address
// plan each holds, and the order they were started in. The runner holds at
// most one claimed instance at a time (it claims only a fresh instance, which
// its case ends), and that one is the newest: the build side of the
// attachment is the newest open instance's.
type book[T comparable] struct {
	mu    sync.Mutex
	slots [Slots]bool
	open  []T
}

// take reserves the lowest free slot and an instance number that the
// process has not used before.
func (b *book[T]) take() (slot, id int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for s, used := range b.slots {
		if !used {
			b.slots[s] = true
			return s, int(instances.Add(1)), nil
		}
	}
	return 0, 0, fmt.Errorf("the sandbox holds %d instances already, all it has addresses for", Slots)
}

// add records v as the newest open instance.
func (b *book[T]) add(v T) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.open = append(b.open, v)
}

// release frees slot; v, when recorded, is no longer open.
func (b *book[T]) release(v T, slot int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.slots[slot] = false
	b.open = slices.DeleteFunc(b.open, func(e T) bool { return e == v })
}

// newest is the open instance started last.
func (b *book[T]) newest() (T, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.open) == 0 {
		var zero T
		return zero, false
	}
	return b.open[len(b.open)-1], true
}
