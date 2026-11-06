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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegionHostsResolve(t *testing.T) {
	regions := RegionHosts{Default: "us", Hosts: map[string]string{"us": "https://us.example", "eu": "https://eu.example", "ap": "https://ap.example"}}
	assert.Equal(t, []string{"us", "ap", "eu"}, regions.Names())

	tests := []struct {
		name, region, host, wantRegion, wantHost, wantErr string
	}{
		{name: "default", wantRegion: "us", wantHost: "https://us.example"},
		{name: "upper case from v2", region: "EU", wantRegion: "eu", wantHost: "https://eu.example"},
		{name: "explicit host wins", region: "eu", host: "https://proxy.example", wantRegion: "eu", wantHost: "https://proxy.example"},
		{name: "unknown", region: "mars", wantErr: `region: must be us/ap/eu`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			region, host := tt.region, tt.host
			errs := regions.Resolve(&region, &host)
			if tt.wantErr != "" {
				assert.Contains(t, errs.Error(), tt.wantErr)
				return
			}
			assert.Empty(t, errs)
			assert.Equal(t, tt.wantRegion, region)
			assert.Equal(t, tt.wantHost, host)
		})
	}
}

func TestRegionSchema(t *testing.T) {
	regions := RegionHosts{Default: "us", Hosts: map[string]string{"us": "https://us.example", "eu": "https://eu.example"}}
	field := regions.SchemaField("Region")
	assert.Equal(t, []string{"us", "eu"}, field.Values)
	assert.Equal(t, "us", field.Default)

	for _, f := range RegionTargetSchemaFields(&HTTPTargetOptions{DefaultHost: "https://us.example", DriverRoutes: true}) {
		if f.Name == "host" {
			assert.Nil(t, f.Default, "the region selects the host")
		}
	}
}

func TestIsAbsoluteHTTPURL(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://example.com/a.png": true, "http://h": true,
		"/a.png": false, "file:///etc/passwd": false, "https://": false, "::": false,
	} {
		assert.Equal(t, want, IsAbsoluteHTTPURL(raw), raw)
	}
}
