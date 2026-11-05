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

package shared

import (
	"fmt"
	"slices"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const fieldHost = "host"

// RegionHosts maps the regions of a SaaS destination to their default
// hosts. An explicit host overrides the region's.
type RegionHosts struct {
	Hosts   map[string]string
	Default string
}

// Names returns the regions in order, the default first.
func (r RegionHosts) Names() []string {
	names := []string{r.Default}
	for name := range r.Hosts {
		if name != r.Default {
			names = append(names, name)
		}
	}
	slices.Sort(names[1:])
	return names
}

// Resolve lowercases region, applies the default when it is empty, and
// fills host from the region when host is empty.
func (r RegionHosts) Resolve(region, host *string) utils.ValidationErrors {
	var errs utils.ValidationErrors
	*region = strings.ToLower(*region)
	if *region == "" {
		*region = r.Default
	}
	regionHost, ok := r.Hosts[*region]
	if !ok {
		errs.Add("region", fmt.Sprintf("must be %s, got %q", strings.Join(r.Names(), "/"), *region))
		return errs
	}
	if *host == "" {
		*host = regionHost
	}
	return nil
}

// SchemaField describes the region enum.
func (r RegionHosts) SchemaField(label string) output.SchemaField {
	return output.SchemaField{Name: "region", Type: "enum", Values: r.Names(), Default: r.Default, Label: label}
}

// RegionTargetSchemaFields returns the target fields with host left without
// a default, since the region selects it.
func RegionTargetSchemaFields(opts *HTTPTargetOptions) []output.SchemaField {
	fields := HTTPTargetSchemaFields(opts)
	for i := range fields {
		if fields[i].Name == fieldHost {
			fields[i].Default = nil
			fields[i].Label = "Host (scheme, host and port; default from region)"
		}
	}
	return fields
}
