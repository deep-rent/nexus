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

	"github.com/deep-rent/nexus/internal/hlc"
)

func TestPackUnpack(t *testing.T) {
	t.Parallel()

	expP := uint64(1717901000)
	expL := uint64(42)

	packed := hlc.Pack(expP, expL)
	actP, actL := hlc.Unpack(packed)

	if actP != expP {
		t.Errorf("expected physical %d, got %d", expP, actP)
	}
	if actL != expL {
		t.Errorf("expected logical %d, got %d", expL, actL)
	}
}

func TestClock_Now(t *testing.T) {
	t.Parallel()

	clock := hlc.New()

	t1 := clock.Now()
	t2 := clock.Now()

	if t1 >= t2 {
		t.Errorf("expected strictly monotonic timestamps, t1=%d, t2=%d", t1, t2)
	}
}

func TestClock_Update(t *testing.T) {
	t.Parallel()

	clock := hlc.New()

	t1 := clock.Now()

	p1, _ := hlc.Unpack(t1)
	remoteOld := hlc.Pack(p1-1000, 5)

	t2, err := clock.Update(remoteOld)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if t2 <= t1 {
		t.Errorf("expected updated timestamp %d to be > %d", t2, t1)
	}

	remoteNew := hlc.Pack(p1+500, 0)
	t3, err := clock.Update(remoteNew)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if t3 <= remoteNew {
		t.Errorf("expected updated timestamp %d to be strictly > remote %d",
			t3, remoteNew)
	}
}

func TestClock_Update_Drift(t *testing.T) {
	t.Parallel()

	clock := hlc.New()

	pt := uint64(time.Now().UnixMilli())
	future := hlc.Pack(pt+(2*60*60*1000), 0)

	_, err := clock.Update(future)
	if !errors.Is(err, hlc.ErrClockDriftTooLarge) {
		t.Errorf("expected clock drift error, got %v", err)
	}
}

func TestClock_Update_Overflow(t *testing.T) {
	t.Parallel()

	clock := hlc.New()

	pt := uint64(time.Now().UnixMilli())

	futureP := pt + 1000
	futureL := uint64((1 << 16) - 1)
	remote := hlc.Pack(futureP, futureL)

	_, err := clock.Update(remote)
	if !errors.Is(err, hlc.ErrLogicalOverflow) {
		t.Errorf("expected ErrLogicalOverflow, got %v", err)
	}
}
