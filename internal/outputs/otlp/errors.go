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

package otlp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

const codePartialSuccess = "partial success"

// Retry rules of the OTLP specification: https://opentelemetry.io/docs/specs/otlp/#failures
var (
	// retriableCodes are the gRPC codes a client may retry; ResourceExhausted only with RetryInfo.
	retriableCodes = map[codes.Code]bool{
		codes.Canceled: true, codes.DeadlineExceeded: true, codes.Aborted: true,
		codes.OutOfRange: true, codes.Unavailable: true, codes.DataLoss: true,
	}
	// retriableHTTPStatus are the HTTP statuses a client may retry; every other 4xx and 5xx must not be.
	retriableHTTPStatus = map[int]bool{
		http.StatusTooManyRequests: true, http.StatusBadGateway: true,
		http.StatusServiceUnavailable: true, http.StatusGatewayTimeout: true,
	}
)

// exportResult is what the transport saw of one export, since the exporters return it only inside text:
// the HTTP status, or a gRPC response that reported a partial success.
type exportResult struct {
	httpStatus int
	partial    bool
}

type resultKey struct{}

func withResult(ctx context.Context, result *exportResult) context.Context {
	return context.WithValue(ctx, resultKey{}, result)
}

func resultFrom(ctx context.Context) *exportResult {
	result, _ := ctx.Value(resultKey{}).(*exportResult)
	return result
}

// statusRecorder records the HTTP status of each export.
type statusRecorder struct{ base http.RoundTripper }

func (r statusRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.base.RoundTrip(req)
	if result := resultFrom(req.Context()); result != nil && resp != nil {
		result.httpStatus = resp.StatusCode
	}
	return resp, err
}

// recordPartialSuccess records a gRPC export response whose partial_success field is set,
// which the specification defines as some data rejected for good.
func recordPartialSuccess(
	ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption,
) error {
	err := invoker(ctx, method, req, reply, cc, opts...)
	if result := resultFrom(ctx); result != nil && err == nil {
		if msg, ok := reply.(proto.Message); ok {
			result.partial = hasPartialSuccess(msg)
		}
	}
	return err
}

func hasPartialSuccess(reply proto.Message) bool {
	m := reply.ProtoReflect()
	field := m.Descriptor().Fields().ByName("partial_success")
	if field == nil || !m.Has(field) {
		return false
	}
	populated := false
	m.Get(field).Message().Range(func(protoreflect.FieldDescriptor, protoreflect.Value) bool {
		populated = true
		return false
	})
	return populated
}

// newDeliveryError classifies a failed export by the OTLP retry rules.
func newDeliveryError(signalName string, result *exportResult, err error) *shared.DeliveryError {
	if st, ok := status.FromError(err); ok && st.Code() != codes.Canceled && st.Code() != codes.DeadlineExceeded {
		return &shared.DeliveryError{
			Cause: err, Output: name, Operation: signalName, Code: st.Code().String(), Permanent: !retriableStatus(st),
		}
	}
	switch {
	case result.partial:
		return &shared.DeliveryError{Cause: err, Output: name, Operation: signalName, Code: codePartialSuccess, Permanent: true}
	case isTransportFailure(err) || result.httpStatus == 0:
		return shared.NewDeliveryError(name, signalName, err)
	case result.httpStatus < http.StatusMultipleChoices:
		// The collector accepted the request and reported rejected items: retrying would duplicate the rest.
		return &shared.DeliveryError{Cause: err, Output: name, Operation: signalName, Code: codePartialSuccess, Permanent: true}
	default:
		return &shared.DeliveryError{
			Cause: err, Output: name, Operation: signalName, Status: result.httpStatus,
			Permanent: !retriableHTTPStatus[result.httpStatus],
		}
	}
}

func retriableStatus(st *status.Status) bool {
	if st.Code() != codes.ResourceExhausted {
		return retriableCodes[st.Code()]
	}
	for _, detail := range st.Details() {
		if _, ok := detail.(*errdetails.RetryInfo); ok {
			return true
		}
	}
	return false
}

// isTransportFailure reports a request no response settled, such as a refused redirect: the HTTP client returns *url.Error.
func isTransportFailure(err error) bool {
	_, ok := errors.AsType[*url.Error](err)
	return ok
}

// joinFailures reports several failed signals; the batch is permanent only when every signal failed for good.
func joinFailures(ctx context.Context, failures []*shared.DeliveryError) *shared.DeliveryError {
	reasons := make([]string, len(failures))
	permanent := true
	for i, failure := range failures {
		reasons[i] = failure.Operation + ": " + failure.Reason()
		permanent = permanent && output.IsPermanent(failure)
	}
	return &shared.DeliveryError{
		Cause: ctx.Err(), Output: name, Operation: shared.OpSend, Code: strings.Join(reasons, "; "), Permanent: permanent,
	}
}
