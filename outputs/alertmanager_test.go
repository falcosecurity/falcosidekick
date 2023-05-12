package outputs

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

const defaultThresholds = `[{"priority":"critical", "value":10000}, {"priority":"critical", "value":1000}, {"priority":"critical", "value":100} ,{"priority":"warning", "value":10}, {"priority":"warning", "value":1}]`

func TestNewAlertmanagerPayloadO(t *testing.T) {
	expectedOutput := `[{"labels":{"proc_name":"falcosidekick","priority":"Debug","severity": "information","proc_tty":"1234","eventsource":"syscalls","hostname":"test-host","rule":"Test rule","source":"falco","tags":"test,example"},"annotations":{"info":"This is a test from falcosidekick","description":"This is a test from falcosidekick","summary":"Test rule"}}]`
	var f types.FalcoPayload
	d := json.NewDecoder(strings.NewReader(falcoTestInput))
	d.UseNumber()
	err := d.Decode(&f) //have to decode it the way newFalcoPayload does
	require.Nil(t, err)

	config := &types.Configuration{
		Alertmanager: types.AlertmanagerOutputConfig{DropEventDefaultPriority: Critical},
	}
	json.Unmarshal([]byte(defaultThresholds), &config.Alertmanager.DropEventThresholdsList)

	s, err := json.Marshal(newAlertmanagerPayload(f, config))
	require.Nil(t, err)

	var o1, o2 []alertmanagerPayload
	require.Nil(t, json.Unmarshal([]byte(expectedOutput), &o1))
	require.Nil(t, json.Unmarshal(s, &o2))

	require.Equal(t, o1, o2)
}

func TestNewAlertmanagerPayloadDropEvent(t *testing.T) {
	input := `{"hostname":"host","output":"Falco internal: syscall event drop. 815508 system calls dropped in last second.","output_fields":{"ebpf_enabled":"1","n_drops":"815508","n_drops_buffer_clone_fork_enter":"0","n_drops_buffer_clone_fork_exit":"0","n_drops_buffer_connect_enter":"0","n_drops_buffer_connect_exit":"0","n_drops_buffer_dir_file_enter":"803","n_drops_buffer_dir_file_exit":"804","n_drops_buffer_execve_enter":"0","n_drops_buffer_execve_exit":"0","n_drops_buffer_open_enter":"798","n_drops_buffer_open_exit":"798","n_drops_buffer_other_interest_enter":"0","n_drops_buffer_other_interest_exit":"0","n_drops_buffer_total":"815508","n_drops_bug":"0","n_drops_page_faults":"0","n_drops_scratch_map":"0","n_evts":"2270350"},"priority":"Debug","rule":"Falco internal: syscall event drop","time":"2023-03-03T03:03:03.000000003Z"}`
	expectedOutput := `[{"labels":{"ebpf_enabled":"1","eventsource":"","hostname":"host","n_drops":">10000","n_drops_buffer_clone_fork_enter":"0","n_drops_buffer_clone_fork_exit":"0","n_drops_buffer_connect_enter":"0","n_drops_buffer_connect_exit":"0","n_drops_buffer_dir_file_enter":">100","n_drops_buffer_dir_file_exit":">100","n_drops_buffer_execve_enter":"0","n_drops_buffer_execve_exit":"0","n_drops_buffer_open_enter":">100","n_drops_buffer_open_exit":">100","n_drops_buffer_other_interest_enter":"0","n_drops_buffer_other_interest_exit":"0","n_drops_buffer_total":">10000","n_drops_bug":"0","n_drops_page_faults":"0","n_drops_scratch_map":"0","priority":"Critical","rule":"Falco internal: syscall event drop","source":"falco"},"annotations":{"description":"Falco internal: syscall event drop. 815508 system calls dropped in last second.","info":"Falco internal: syscall event drop. 815508 system calls dropped in last second.","summary":"Falco internal: syscall event drop"},"endsAt":"0001-01-01T00:00:00Z"}]`
	var f types.FalcoPayload
	d := json.NewDecoder(strings.NewReader(input))
	d.UseNumber()
	err := d.Decode(&f) //have to decode it the way newFalcoPayload does
	require.Nil(t, err)

	config := &types.Configuration{
		Alertmanager: types.AlertmanagerOutputConfig{DropEventDefaultPriority: Critical},
	}
	json.Unmarshal([]byte(defaultThresholds), &config.Alertmanager.DropEventThresholdsList)

	s, err := json.Marshal(newAlertmanagerPayload(f, config))
	require.Nil(t, err)

	var o1, o2 []alertmanagerPayload
	require.Nil(t, json.Unmarshal([]byte(expectedOutput), &o1))
	require.Nil(t, json.Unmarshal(s, &o2))

	require.Equal(t, o1, o2)
}
