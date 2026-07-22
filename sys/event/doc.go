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

// Package event provides a high-performance, in-memory event bus system.
//
// It relies on a lock-free ring buffer for low-latency event publishing and an
// atomic copy-on-write mechanism for thread-safe subscriber management. The
// package offers both standalone event streams ([Bus]) and a centralized topic
// manager ([Broker]) for safely routing different event types across an
// application.
//
// # Usage
//
// A typical setup involves initializing a [Broker], retrieving a typed [Bus]
// for a topic, and subscribing to or publishing events.
//
// Example:
//
//	type UserCreated struct {
//		Email string
//	}
//
//	// 1. Initialize the central broker with options.
//	broker := event.NewBroker(event.WithSyncDispatch())
//	defer broker.Close()
//
//	// 2. Retrieve a typed bus for a specific topic.
//	bus := event.Topic[UserCreated](broker, "users.created")
//
//	// 3. Subscribe to the event stream.
//	unsub := bus.Subscribe(func(e UserCreated) {
//		fmt.Println("New user registered:", e.Email)
//	})
//	defer unsub()
//
//	// 4. Publish an event.
//	bus.Publish(UserCreated{Email: "alice@example.com"})
package event
