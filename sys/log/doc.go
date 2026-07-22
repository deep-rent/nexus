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

// Package log provides a configurable constructor for the standard
// [slog.Logger], allowing for easy setup using the functional options pattern.
// It simplifies the creation of a structured logger by abstracting away the
// handler setup and providing flexible options for setting the level, format,
// and output from common types like strings.
//
// # Usage
//
// Create a logger that outputs JSON at a debug level to standard error:
//
// Example:
//
//	logger := log.New(
//	  log.WithLevel(slog.LevelDebug),
//	  log.WithFormat(log.FormatJSON),
//	  log.WithWriter(os.Stderr),
//	  log.WithAddSource(true), // Include file and line number.
//	)
//
// Levels and formats can also be parsed from configuration strings with
// [ParseLevel] and [ParseFormat].
//
//	slog.SetDefault(logger)
//	slog.Debug("This is a debug message")
//
// Create a multi-target logger using Combine and NewHandler:
//
// Example:
//
//	h1 := log.NewHandler(
//	  log.WithLevel(slog.LevelDebug),
//	  log.WithFormat(FormatText),
//	  log.WithWriter(os.Stdout),
//	)
//	h2 := log.NewHandler(
//	  log.WithLevel(slog.LevelError),
//	  log.WithFormat(FormatJSON),
//	  log.WithWriter(os.Stderr),
//	)
//	multiLogger := log.Combine(h1, h2)
//
//	slog.SetDefault(multiLogger)
//	slog.Debug("This is a debug message")
package log
