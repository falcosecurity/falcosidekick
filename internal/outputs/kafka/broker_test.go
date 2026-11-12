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

package kafka

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kbin"
	"github.com/twmb/franz-go/pkg/kmsg"
)

// brokerMode is what fakeBroker does with a produce request.
type brokerMode int32

const (
	// modeAnswer acknowledges every produce request.
	modeAnswer brokerMode = iota
	// modeHold reads a produce request and never answers it, keeping the connection open.
	modeHold
	// modeGone reads a produce request, then closes the listener and every connection.
	modeGone
)

// fakeBroker is a single-node Kafka broker answering ApiVersions, Metadata, InitProducerID and Produce; it does not decode records.
type fakeBroker struct {
	t        *testing.T
	ln       net.Listener
	conns    map[net.Conn]struct{}
	lost     chan struct{}
	addr     string
	topic    string
	wg       sync.WaitGroup
	mu       sync.Mutex
	offset   atomic.Int64
	answered atomic.Int64
	mode     atomic.Int32
	lostOnce sync.Once
}

// supported caps every key below the versions that need topic IDs.
var supported = map[int16][2]int16{
	0:  {3, 9}, // Produce
	3:  {0, 9}, // Metadata
	18: {0, 3}, // ApiVersions
	22: {0, 4}, // InitProducerID
}

// newFakeBroker serves warmTopic with one partition.
func newFakeBroker(t *testing.T) *fakeBroker {
	t.Helper()
	b := &fakeBroker{t: t, topic: warmTopic, conns: make(map[net.Conn]struct{}), lost: make(chan struct{})}
	b.listen("127.0.0.1:0")
	t.Cleanup(func() {
		b.stop()
		b.wg.Wait()
	})
	return b
}

func (b *fakeBroker) listen(addr string) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	require.NoError(b.t, err)
	b.mu.Lock()
	b.ln, b.addr = ln, ln.Addr().String()
	b.mu.Unlock()
	b.wg.Go(func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			b.mu.Lock()
			b.conns[conn] = struct{}{}
			b.mu.Unlock()
			b.wg.Go(func() { b.serve(conn) })
		}
	})
}

// restart listens again on the same address and answers every request.
func (b *fakeBroker) restart() {
	b.mode.Store(int32(modeAnswer))
	b.listen(b.addr)
}

// stop closes the listener and every connection, as a broker that went away.
func (b *fakeBroker) stop() {
	b.mu.Lock()
	if b.ln != nil {
		_ = b.ln.Close()
	}
	for conn := range b.conns {
		_ = conn.Close()
		delete(b.conns, conn)
	}
	b.mu.Unlock()
}

func (b *fakeBroker) serve(conn net.Conn) {
	defer func() {
		b.mu.Lock()
		delete(b.conns, conn)
		b.mu.Unlock()
		_ = conn.Close()
	}()
	var size [4]byte
	for {
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		body := make([]byte, binary.BigEndian.Uint32(size[:]))
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		resp, corr, ok := b.handle(body)
		if !ok {
			continue
		}
		if resp == nil {
			// Broker gone: the request was read and will never be answered.
			b.stop()
			return
		}
		buf := kbin.AppendInt32(make([]byte, 4, 128), corr)
		if resp.IsFlexible() && resp.Key() != 18 {
			buf = append(buf, 0)
		}
		buf = resp.AppendTo(buf)
		binary.BigEndian.PutUint32(buf, uint32(len(buf)-4))
		if _, err := conn.Write(buf); err != nil {
			return
		}
	}
}

// handle returns the response for one request; ok false holds it unanswered, a nil response with ok true means the broker goes away.
func (b *fakeBroker) handle(body []byte) (kmsg.Response, int32, bool) {
	r := kbin.Reader{Src: body}
	key, version, corr := r.Int16(), r.Int16(), r.Int32()
	r.NullableString()
	req := kmsg.RequestForKey(key)
	if req == nil {
		b.t.Errorf("fake broker: unexpected request key %d", key)
		return nil, corr, false
	}
	req.SetVersion(version)
	if req.IsFlexible() {
		kmsg.SkipTags(&r)
	}
	if err := req.ReadFrom(r.Src); err != nil {
		b.t.Errorf("fake broker: decode key %d v%d: %v", key, version, err)
		return nil, corr, false
	}
	resp := req.ResponseKind()
	resp.SetVersion(version)
	switch req := req.(type) {
	case *kmsg.ApiVersionsRequest:
		b.apiVersions(resp.(*kmsg.ApiVersionsResponse))
	case *kmsg.MetadataRequest:
		b.metadata(resp.(*kmsg.MetadataResponse))
	case *kmsg.InitProducerIDRequest:
		init := resp.(*kmsg.InitProducerIDResponse)
		init.ProducerID = b.offset.Add(1)
	case *kmsg.ProduceRequest:
		switch brokerMode(b.mode.Load()) {
		case modeHold:
			b.lostOnce.Do(func() { close(b.lost) })
			return nil, corr, false
		case modeGone:
			b.lostOnce.Do(func() { close(b.lost) })
			return nil, corr, true
		case modeAnswer:
		}
		b.produce(req, resp.(*kmsg.ProduceResponse))
		b.answered.Add(1)
	default:
		b.t.Errorf("fake broker: unhandled request key %d", key)
		return nil, corr, false
	}
	return resp, corr, true
}

func (b *fakeBroker) apiVersions(resp *kmsg.ApiVersionsResponse) {
	for key, versions := range supported {
		k := kmsg.NewApiVersionsResponseApiKey()
		k.ApiKey, k.MinVersion, k.MaxVersion = key, versions[0], versions[1]
		resp.ApiKeys = append(resp.ApiKeys, k)
	}
}

func (b *fakeBroker) metadata(resp *kmsg.MetadataResponse) {
	host, portText, _ := net.SplitHostPort(b.addr)
	port, _ := strconv.ParseInt(portText, 10, 32)
	broker := kmsg.NewMetadataResponseBroker()
	broker.NodeID, broker.Host, broker.Port = 0, host, int32(port)
	resp.Brokers = []kmsg.MetadataResponseBroker{broker}
	resp.ControllerID = 0
	topic := kmsg.NewMetadataResponseTopic()
	topic.Topic = kmsg.StringPtr(b.topic)
	partition := kmsg.NewMetadataResponseTopicPartition()
	partition.Replicas, partition.ISR = []int32{0}, []int32{0}
	topic.Partitions = []kmsg.MetadataResponseTopicPartition{partition}
	resp.Topics = []kmsg.MetadataResponseTopic{topic}
}

func (b *fakeBroker) produce(req *kmsg.ProduceRequest, resp *kmsg.ProduceResponse) {
	for _, reqTopic := range req.Topics {
		topic := kmsg.NewProduceResponseTopic()
		topic.Topic = reqTopic.Topic
		for _, reqPartition := range reqTopic.Partitions {
			partition := kmsg.NewProduceResponseTopicPartition()
			partition.Partition = reqPartition.Partition
			partition.BaseOffset = b.offset.Add(1)
			topic.Partitions = append(topic.Partitions, partition)
		}
		resp.Topics = append(resp.Topics, topic)
	}
}
