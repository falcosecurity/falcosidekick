// Copyright (C) 2026 The Falco Authors
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
//
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"errors"
	"fmt"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/config"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// ErrInvalidOutputConfig matches BuildOutput failures caused by the supplied
// configuration, as opposed to driver initialization.
var ErrInvalidOutputConfig = errors.New("invalid output config")

type invalidOutputConfigError struct{ cause error }

func (e invalidOutputConfigError) Error() string        { return e.cause.Error() }
func (e invalidOutputConfigError) Unwrap() error        { return e.cause }
func (e invalidOutputConfigError) Is(target error) bool { return target == ErrInvalidOutputConfig }

// BuildOutput constructs a live *Output. On any failure after
// catalog.Create, the driver is closed before return. Secret resolution
// is the caller's responsibility.
func BuildOutput(
	ctx context.Context,
	cat *catalog.Catalog,
	name string,
	cfg map[string]any,
	defaults output.RuntimeConfig,
	deps output.Deps,
) (*Output, error) {
	driver, err := cat.Create(name, cfg, deps)
	if err != nil {
		return nil, fmt.Errorf("create: %w", invalidOutputConfigError{cause: err})
	}

	if err := driver.Init(ctx); err != nil {
		_ = driver.Close()
		return nil, fmt.Errorf("init: %w", err)
	}

	merged, err := config.MergeRuntimeConfig(defaults, name, driver.RuntimeConfig())
	if err != nil {
		_ = driver.Close()
		return nil, fmt.Errorf("runtime merge: %w", invalidOutputConfigError{cause: err})
	}

	return NewOutput(driver, &merged, deps.Metrics), nil
}
