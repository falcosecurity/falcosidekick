// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package types

import (
	"reflect"
	"testing"
)

func TestPriorityType_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		p       PriorityType
		want    []byte
		wantErr bool
	}{{
		name: "Default",
		p:    Default,
		want: []byte(`""`),
	}, {
		name: "Debug",
		p:    Debug,
		want: []byte(`"Debug"`),
	}, {
		name: "Informational",
		p:    Informational,
		want: []byte(`"Informational"`),
	}, {
		name: "Notice",
		p:    Notice,
		want: []byte(`"Notice"`),
	}, {
		name: "Warning",
		p:    Warning,
		want: []byte(`"Warning"`),
	}, {
		name: "Error",
		p:    Error,
		want: []byte(`"Error"`),
	}, {
		name: "Critical",
		p:    Critical,
		want: []byte(`"Critical"`),
	}, {
		name: "Alert",
		p:    Alert,
		want: []byte(`"Alert"`),
	}, {
		name: "Emergency",
		p:    Emergency,
		want: []byte(`"Emergency"`),
	}, {
		name: "Unknown Key",
		p:    42,
		want: []byte(`""`),
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.p.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MarshalJSON() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPriorityType_UnmarshalJSON(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name    string
		p       PriorityType
		args    args
		wantErr bool
	}{{
		name: "Default",
		p:    Default,
		args: args{b: []byte(`""`)},
	}, {
		name: "Debug",
		p:    Debug,
		args: args{b: []byte(`"Debug"`)},
	}, {
		name: "Informational",
		p:    Informational,
		args: args{b: []byte(`"Informational"`)},
	}, {
		name: "Notice",
		p:    Notice,
		args: args{b: []byte(`"Notice"`)},
	}, {
		name: "Warning",
		p:    Warning,
		args: args{b: []byte(`"Warning"`)},
	}, {
		name: "Error",
		p:    Error,
		args: args{b: []byte(`"Error"`)},
	}, {
		name: "Critical",
		p:    Critical,
		args: args{b: []byte(`"Critical"`)},
	}, {
		name: "Alert",
		p:    Alert,
		args: args{b: []byte(`"Alert"`)},
	}, {
		name: "Emergency",
		p:    Emergency,
		args: args{b: []byte(`"Emergency"`)},
	}, {
		name: "Unknown Key",
		p:    42,
		args: args{b: []byte(`"Call me, maybe?"`)},
	}, {
		name:    "an error",
		wantErr: true,
		args:    args{b: []byte(`totes an error`)},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.UnmarshalJSON(tt.args.b); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPriority(t *testing.T) {
	tests := []struct {
		name string
		p    string
		want PriorityType
	}{{
		name: "Default",
		p:    "",
		want: Default,
	}, {
		name: "Debug",
		p:    "Debug",
		want: Debug,
	}, {
		name: "Informational",
		p:    "Informational",
		want: Informational,
	}, {
		name: "Notice",
		p:    "Notice",
		want: Notice,
	}, {
		name: "Warning",
		p:    "Warning",
		want: Warning,
	}, {
		name: "Error",
		p:    "Error",
		want: Error,
	}, {
		name: "Critical",
		p:    "Critical",
		want: Critical,
	}, {
		name: "Alert",
		p:    "Alert",
		want: Alert,
	}, {
		name: "Unknown Key",
		p:    "idk",
		want: Default,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Priority(tt.p); got != tt.want {
				t.Errorf("Priority() = %v, want %v", got, tt.want)
			}
		})
	}
}
