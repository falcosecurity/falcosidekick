package main

import "testing"

func TestKubernetesFieldsIgnoresNonStringValues(t *testing.T) {
	// output_fields is decoded from the request body, so a field can hold any
	// JSON value. A bare j.(string) panicked on all of these.
	tests := map[string]map[string]interface{}{
		"namespace as a number":  {"k8s.ns.name": 42},
		"pod as a number":        {"k8s.pod.name": 42},
		"namespace as an object": {"k8s.ns.name": map[string]interface{}{"a": 1}},
		"pod as a list":          {"k8s.pod.name": []interface{}{"a"}},
		"namespace as a bool":    {"k8s.ns.name": true},
		"nil value":              {"k8s.ns.name": nil},
	}

	for name, outputFields := range tests {
		t.Run(name, func(t *testing.T) {
			namespace, pod := kubernetesFields(outputFields)

			if namespace != "" || pod != "" {
				t.Fatalf("expected both empty, got namespace=%q pod=%q", namespace, pod)
			}
		})
	}
}

func TestKubernetesFieldsKeepsStringValues(t *testing.T) {
	namespace, pod := kubernetesFields(map[string]interface{}{
		"k8s.ns.name":  "kube-system",
		"k8s.pod.name": "falco-abcde",
		"proc.name":    "falco",
	})

	if namespace != "kube-system" {
		t.Fatalf("namespace: got %q", namespace)
	}
	if pod != "falco-abcde" {
		t.Fatalf("pod: got %q", pod)
	}
}

func TestKubernetesFieldsKeepsAStringWhenTheOtherIsNot(t *testing.T) {
	namespace, pod := kubernetesFields(map[string]interface{}{
		"k8s.ns.name":  "kube-system",
		"k8s.pod.name": 42,
	})

	if namespace != "kube-system" {
		t.Fatalf("namespace: got %q", namespace)
	}
	if pod != "" {
		t.Fatalf("pod: got %q", pod)
	}
}
