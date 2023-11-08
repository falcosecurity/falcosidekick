package outputs

import (
	"reflect"
	"testing"
)

func Test_getSortedStringKeys(t *testing.T) {
	type args struct {
		m map[string]interface{}
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "basic sort",
			args: args{
				m: map[string]interface{}{
					"b": "foo",
					"c": "baz",
					"a": "bar",
				},
			},
			want: []string{"a", "b", "c"},
		},
		{
			name: "In place sort",
			args: args{
				m: map[string]interface{}{
					"a": "",
					"b": "",
					"c": "",
				},
			},
			want: []string{"a", "b", "c"},
		},
		{
			name: "Non-string emission",
			args: args{
				m: map[string]interface{}{
					"a": "a",
					"b": 2,
					"c": "c",
				},
			},
			want: []string{"a", "c"},
		},
		{
			name: "Non-string emission - empty result",
			args: args{
				m: map[string]interface{}{
					"a": 1,
					"b": 2,
					"c": 3,
				},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getSortedStringKeys(tt.args.m); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getSortedStringKeys() = %v, want %v", got, tt.want)
			}
		})
	}
}
