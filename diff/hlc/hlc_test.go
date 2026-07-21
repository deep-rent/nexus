// Copyright (c) 2025-present deep.rent GmbH (https://deep.rent)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hlc_test

import (
	"errors"
	"testing"
	"time"

	"github.com/deep-rent/nexus/diff/hlc"
)

func TestPackUnpack(t *testing.T) {
	t.Parallel()

	expP := uint64(1717901000)
	expL := uint64(42)

	packed := hlc.Pack(expP, expL)
	actP, actL := hlc.Unpack(packed)

	if actP != expP {
		t.Errorf("physical: got %d; want %d", actP, expP)
	}
	if actL != expL {
		t.Errorf("logical: got %d; want %d", actL, expL)
	}
}

func TestPackUnpack_Bounds(t *testing.T) {
	t.Parallel()

	expP := uint64(1<<33 - 1)
	expL := uint64(1<<20 - 1)

	packed := hlc.Pack(expP, expL)

	if packed != hlc.Max {
		t.Errorf("packed maximum: got %d; want %d", packed, uint64(hlc.Max))
	}

	actP, actL := hlc.Unpack(packed)
	if actP != expP {
		t.Errorf("physical: got %d; want %d", actP, expP)
	}
	if actL != expL {
		t.Errorf("logical: got %d; want %d", actL, expL)
	}
}

func TestClock_Now(t *testing.T) {
	t.Parallel()

	clock := hlc.New(nil)

	t1 := clock.Now()
	t2 := clock.Now()

	if t1 >= t2 {
		t.Errorf("timestamps should be strictly monotonic; got t1=%d, t2=%d",
			t1, t2)
	}
	if t2 > hlc.Max {
		t.Errorf("got timestamp %d; want at most %d", t2, uint64(hlc.Max))
	}
}

func TestClock_Update(t *testing.T) {
	t.Parallel()

	clock := hlc.New(nil)

	t1 := clock.Now()

	p1, _ := hlc.Unpack(t1)
	remoteOld := hlc.Pack(p1-100, 5)

	t2, err := clock.Update(remoteOld)
	if err != nil {
		t.Fatalf("for old remote: should not have returned an error: %v", err)
	}
	if t2 <= t1 {
		t.Errorf("for old remote: got timestamp %d; want greater than %d",
			t2, t1)
	}

	remoteNew := hlc.Pack(p1+30, 0)
	t3, err := clock.Update(remoteNew)
	if err != nil {
		t.Fatalf("for new remote: should not have returned an error: %v", err)
	}

	if t3 <= remoteNew {
		t.Errorf("for new remote: got timestamp %d; want strictly greater "+
			"than %d", t3, remoteNew)
	}
}

func TestClock_Update_Drift(t *testing.T) {
	t.Parallel()

	clock := hlc.New(nil)

	pt := uint64(time.Now().Unix())
	future := hlc.Pack(pt+(2*60*60), 0)

	_, err := clock.Update(future)
	if !errors.Is(err, hlc.ErrClockDriftTooLarge) {
		t.Errorf("got error %v; want ErrClockDriftTooLarge", err)
	}
}

func TestClock_Update_Oversized(t *testing.T) {
	t.Parallel()

	clock := hlc.New(nil)

	_, err := clock.Update(hlc.Time(uint64(hlc.Max) + 1))
	if !errors.Is(err, hlc.ErrClockDriftTooLarge) {
		t.Errorf("got error %v; want ErrClockDriftTooLarge", err)
	}
}

func TestClock_Update_Overflow(t *testing.T) {
	t.Parallel()

	clock := hlc.New(nil)

	pt := uint64(time.Now().Unix())

	futureP := pt + 30
	futureL := uint64((1 << 20) - 1)
	remote := hlc.Pack(futureP, futureL)

	_, err := clock.Update(remote)
	if !errors.Is(err, hlc.ErrLogicalOverflow) {
		t.Errorf("got error %v; want ErrLogicalOverflow", err)
	}
}
