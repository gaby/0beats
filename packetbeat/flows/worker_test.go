// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package flows

import (
	"encoding/json"
	"flag"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/packetbeat/procs"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/go-lookslike"
	"github.com/elastic/go-lookslike/isdef"
)

// Use `go test -data` to update sample event files.
var dataFlag = flag.Bool("data", false, "Write updated data.json files")

func TestCreateEvent(t *testing.T) {
	logp.TestingSetup()

	// Build biflow event.
	start := time.Unix(1542292881, 0)
	end := start.Add(3 * time.Second)
	vlan := uint16(171)
	mac1 := []byte{1, 2, 3, 4, 5, 6}
	mac2 := []byte{6, 5, 4, 3, 2, 1}
	ip1 := []byte{203, 0, 113, 3}
	ip2 := []byte{198, 51, 100, 2}
	port1 := uint16(38901)
	port2 := uint16(80)

	id := newFlowID()
	id.AddEth(mac1, mac2)
	id.AddVLan(vlan)
	id.AddIPv4(ip1, ip2)
	id.AddTCP(port1, port2)

	bif := &biFlow{
		id:       id.rawFlowID,
		killed:   1,
		createTS: start,
		ts:       end,
		dir:      flowDirForward,
	}
	bif.stats[0] = &flowStats{uintFlags: []uint8{1, 1}, uints: []uint64{10, 1}}
	bif.stats[1] = &flowStats{uintFlags: []uint8{1, 1}, uints: []uint64{460, 2}}
	snapshot := newFlowSnapshot(bif, true, nil, []string{"bytes", "packets"}, nil, false)
	event := createEvent(&procs.ProcessesWatcher{}, time.Now(), &snapshot)

	// Validate the contents of the event.
	validate := lookslike.MustCompile(map[string]interface{}{
		"source": map[string]interface{}{
			"mac":     "01-02-03-04-05-06",
			"ip":      "203.0.113.3",
			"port":    port1,
			"bytes":   uint64(10),
			"packets": uint64(1),
		},
		"destination": map[string]interface{}{
			"mac":     "06-05-04-03-02-01",
			"ip":      "198.51.100.2",
			"port":    port2,
			"bytes":   uint64(460),
			"packets": uint64(2),
		},
		"flow": map[string]interface{}{
			"id":    isdef.KeyPresent,
			"final": true,
			"vlan":  isdef.KeyPresent,
		},
		"network": map[string]interface{}{
			"bytes":     uint64(470),
			"packets":   uint64(3),
			"type":      "ipv4",
			"transport": "tcp",
		},
		"event": map[string]interface{}{
			"start":    isdef.KeyPresent,
			"end":      isdef.KeyPresent,
			"duration": isdef.KeyPresent,
			"dataset":  "flow",
			"kind":     "event",
			"category": []string{"network"},
			"action":   "network_flow",
		},
		"type": "flow",
	})

	result := validate(event.Fields)
	if errs := result.Errors(); len(errs) > 0 {
		for _, err := range errs {
			t.Error(err)
		}
		t.FailNow()
	}

	// Write the event to disk if -data is used.
	if *dataFlag {
		event.Fields.Put("@timestamp", common.Time(end))
		output, err := json.MarshalIndent(&event.Fields, "", "  ")
		if err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile("../_meta/sample_outputs/flow.json", output, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// when enableDeltaFlowReporting is true, the flow stats should be reset
	expectbiFlow := &biFlow{
		id:       id.rawFlowID,
		killed:   1,
		createTS: start,
		ts:       end,
		dir:      flowDirForward,
	}
	expectbiFlow.stats[0] = &flowStats{uintFlags: []uint8{1, 1}, uints: []uint64{0, 0}}
	expectbiFlow.stats[1] = &flowStats{uintFlags: []uint8{1, 1}, uints: []uint64{0, 0}}

	// Assert the biflow is not 0 before the test
	assert.NotEqual(t, expectbiFlow.stats[0].uints, bif.stats[0].uints)
	assert.NotEqual(t, expectbiFlow.stats[1].uints, bif.stats[1].uints)

	snapshot = newFlowSnapshot(bif, true, nil, []string{"bytes", "packets"}, nil, true)
	event = createEvent(&procs.ProcessesWatcher{}, time.Now(), &snapshot)
	result = validate(event.Fields)
	if errs := result.Errors(); len(errs) > 0 {
		for _, err := range errs {
			t.Error(err)
		}
		t.FailNow()
	}

	// Assert the biflow is 0 after the test
	assert.Equal(t, expectbiFlow.stats[0].uintFlags, bif.stats[0].uintFlags)
	assert.Equal(t, expectbiFlow.stats[0].uints, bif.stats[0].uints)
	assert.Equal(t, expectbiFlow.stats[1].uintFlags, bif.stats[1].uintFlags)
	assert.Equal(t, expectbiFlow.stats[1].uints, bif.stats[1].uints)
}

func TestFlowsProcessorExecuteUnlocksBeforeReporting(t *testing.T) {
	logp.TestingSetup()

	table := &flowMetaTable{
		table: make(map[flowIDMeta]*flowTable),
	}

	id := newFlowID()
	srcIP := net.IP{192, 0, 2, 1}
	dstIP := net.IP{198, 51, 100, 2}
	id.AddIPv4(srcIP, dstIP)
	id.AddTCP(12345, 80)

	now := time.Now()
	flow := &biFlow{
		id:       id.rawFlowID,
		createTS: now.Add(-time.Second),
		ts:       now,
		dir:      flowDirForward,
	}
	flow.stats[0] = &flowStats{
		uintFlags: []uint8{3},
		uints:     []uint64{100, 10},
	}

	ft := &flowTable{
		table: map[string]*biFlow{string(flow.id.flowID): flow},
	}
	ft.flows.append(flow)
	table.table[flow.id.flowIDMeta] = ft
	table.tables.append(ft)

	counters := &counterReg{}
	counters.uints.names = []string{"bytes", "packets"}

	var reported []beat.Event
	reporter := func(events []beat.Event) {
		acquired := make(chan struct{}, 1)
		go func() {
			table.Lock()
			table.Unlock()
			acquired <- struct{}{}
		}()

		select {
		case <-acquired:
		case <-time.After(time.Second):
			t.Fatal("table lock held while publishing events")
		}

		reported = append(reported, events...)
	}

	processor := &flowsProcessor{
		watcher:                  &procs.ProcessesWatcher{},
		table:                    table,
		counters:                 counters,
		enableDeltaFlowReporting: false,
	}
	processor.spool.init(reporter, 10)

	processor.execute(nil, false, true, false)

	if len(reported) != 1 {
		t.Fatalf("expected 1 reported event, got %d", len(reported))
	}

	event := reported[0]
	network, ok := event.Fields["network"].(mapstr.M)
	if !ok {
		t.Fatalf("network fields missing from event: %+v", event.Fields)
	}
	assert.Equal(t, uint64(100), network["bytes"])
	assert.Equal(t, uint64(10), network["packets"])
	assert.Equal(t, "tcp", network["transport"])

	source, ok := event.Fields["source"].(mapstr.M)
	if !ok {
		t.Fatalf("source fields missing from event: %+v", event.Fields)
	}
	assert.Equal(t, "192.0.2.1", source["ip"])
	assert.Equal(t, uint16(12345), source["port"])

	destination, ok := event.Fields["destination"].(mapstr.M)
	if !ok {
		t.Fatalf("destination fields missing from event: %+v", event.Fields)
	}
	assert.Equal(t, "198.51.100.2", destination["ip"])
	assert.Equal(t, uint16(80), destination["port"])
}

func TestFlowsProcessorExecuteResetsStatsWithDeltaReporting(t *testing.T) {
	logp.TestingSetup()

	table := &flowMetaTable{
		table: make(map[flowIDMeta]*flowTable),
	}

	id := newFlowID()
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{10, 0, 0, 2}
	id.AddIPv4(srcIP, dstIP)
	id.AddTCP(5050, 8080)

	now := time.Now()
	flow := &biFlow{
		id:       id.rawFlowID,
		createTS: now.Add(-2 * time.Second),
		ts:       now,
		dir:      flowDirForward,
	}
	flow.stats[0] = &flowStats{
		uintFlags: []uint8{3},
		uints:     []uint64{150, 9},
	}
	flow.stats[1] = &flowStats{
		uintFlags: []uint8{3},
		uints:     []uint64{75, 6},
	}

	ft := &flowTable{
		table: map[string]*biFlow{string(flow.id.flowID): flow},
	}
	ft.flows.append(flow)
	table.table[flow.id.flowIDMeta] = ft
	table.tables.append(ft)

	counters := &counterReg{}
	counters.uints.names = []string{"bytes", "packets"}

	var reported []beat.Event
	reporter := func(events []beat.Event) {
		reported = append(reported, events...)
	}

	processor := &flowsProcessor{
		watcher:                  &procs.ProcessesWatcher{},
		table:                    table,
		counters:                 counters,
		enableDeltaFlowReporting: true,
	}
	processor.spool.init(reporter, 10)

	// Ensure counters are non-zero before executing so we can verify resets later.
	assert.NotEqual(t, []uint64{0, 0}, flow.stats[0].uints)
	assert.NotEqual(t, []uint64{0, 0}, flow.stats[1].uints)

	processor.execute(nil, false, true, false)

	if len(reported) != 1 {
		t.Fatalf("expected 1 reported event, got %d", len(reported))
	}

	event := reported[0]
	network, ok := event.Fields["network"].(mapstr.M)
	if !ok {
		t.Fatalf("network fields missing from event: %+v", event.Fields)
	}
	assert.Equal(t, uint64(225), network["bytes"])
	assert.Equal(t, uint64(15), network["packets"])

	assert.Equal(t, []uint64{0, 0}, flow.stats[0].uints)
	assert.Equal(t, []uint64{0, 0}, flow.stats[1].uints)
}
