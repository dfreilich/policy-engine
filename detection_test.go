package engine_test

import (
	"net"
	"testing"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/assert"

	"github.com/dfreilich/guardicore-policy-engine"
)

func TestDetector(t *testing.T) {
	spec.Run(t, "DetectionResult", testDetector, spec.Parallel(), spec.Report(report.Terminal{}))
}

func testDetector(t *testing.T, when spec.G, it spec.S) {
	when("#NewDetector", func() {
		when("empty inputs", func() {
			it("initializes an empty detector", func() {
				detector := engine.DetectAttacks([]engine.Policy{}, []engine.Connection{})
				assert.Equal(t, detector, engine.DetectionResult{RuleCount: map[string]int{}})
			})
		})

		when("all connections are clean", func() {
			it("initializes a clean detector", func() {
				connections := []engine.Connection{
					{
						Timestamp: "",
						Source: net.ParseIP("192.0.0.15"),
						SourcePort: 5000,
						Destination: net.ParseIP("192.128.0.32"),
						DestinationPort: 51000,
						Protocol: "TCP",
					},
				}

				detector := engine.DetectAttacks([]engine.Policy{
					{
						ID: "c36049aa-f2b3-11ea-aa02-0050569de26b",
						Name: "inspect Martin's laptop",
						IPMap: map[string]interface{}{"192.0.0.3/32":nil},
						Verdict: "INSPECT",
					},
				}, connections)
				assert.Equal(t, detector, engine.DetectionResult{CleanCount: 1, RuleCount: map[string]int{}, NoMatchCount: 1})
			})
		})

		when("there is a match", func() {
			it("initializes a detector with the match", func() {
				connections := []engine.Connection{
					{
						Timestamp: "",
						Source: net.ParseIP("192.0.0.3"),
						SourcePort: 5000,
						Destination: net.ParseIP("192.128.0.32"),
						DestinationPort: 51000,
						Protocol: "TCP",
					},
				}

				detector := engine.DetectAttacks([]engine.Policy{
					{
						ID: "c36049aa-f2b3-11ea-aa02-0050569de26b",
						Name: "inspect Martin's laptop",
						IPMap: map[string]interface{}{"192.0.0.3":nil},
						Verdict: "INSPECT",
					},
				}, connections)

				assert.Equal(t, engine.DetectionResult{
					Suspicious: connections,
					CleanCount: 0,
					RuleCount: map[string]int{
						"inspect Martin's laptop":1,
					},
				}, detector)
			})
		})

		when("there is an IGNORE match", func() {
			it("doesn't find it suspicious", func() {
				connections := []engine.Connection{
					{
						Timestamp: "",
						Source: net.ParseIP("192.0.0.3"),
						SourcePort: 5000,
						Destination: net.ParseIP("192.128.0.32"),
						DestinationPort: 51000,
						Protocol: "TCP",
					},
				}

				detector := engine.DetectAttacks([]engine.Policy{
					{
						ID: "c36049aa-f2b3-11ea-aa02-0050569de26b",
						Name: "inspect Martin's laptop",
						IPMap: map[string]interface{}{"192.0.0.3":nil},
						Verdict: "IGNORE",
					},
				}, connections)

				assert.Equal(t, engine.DetectionResult{
					CleanCount: 1,
					RuleCount: map[string]int{
						"inspect Martin's laptop":1,
					},
				}, detector)
			})
		})

		when("connection matches both IGNORE and INSPECT", func() {
			it("doesn't find it suspicious", func() {
				connections := []engine.Connection{
					{
						Timestamp: "",
						Source: net.ParseIP("192.0.0.3"),
						SourcePort: 5000,
						Destination: net.ParseIP("192.128.0.32"),
						DestinationPort: 51000,
						Protocol: "TCP",
					},
				}

				detector := engine.DetectAttacks([]engine.Policy{
					{
						ID: "c36049aa-f2b3-11ea-aa02-0050569de26b",
						Name: "inspect Martin's laptop",
						IPMap: map[string]interface{}{"192.0.0.3":nil},
						Verdict: "INSPECT",
					},
					{
						ID: "c36049aa-f2b3-11ea-aa02-0050569de26234",
						Name: "inspect Martin's laptop2",
						IPMap: map[string]interface{}{"192.0.0.3":nil},
						Verdict: "IGNORE",
					},
				}, connections)

				assert.Equal(t, engine.DetectionResult{
					CleanCount: 1,
					RuleCount: map[string]int{
						"inspect Martin's laptop":1,
						"inspect Martin's laptop2":1,
					},
				}, detector)
			})
		})

		when("combination of previous cases", func() {
			it("finds appropriate cases suspicious", func() {
				connections := []engine.Connection{
					{
						Timestamp: "",
						Source: net.ParseIP("192.0.0.3"),
						SourcePort: 5000,
						Destination: net.ParseIP("192.128.0.32"),
						DestinationPort: 51000,
						Protocol: "TCP",
					},
					{
						Timestamp: "",
						Source: net.ParseIP("192.0.0.15"),
						SourcePort: 80,
						Destination: net.ParseIP("192.128.0.32"),
						DestinationPort: 51000,
						Protocol: "TCP",
					},
					{
						Timestamp: "",
						Source: net.ParseIP("192.0.0.3"),
						SourcePort: 80,
						Destination: net.ParseIP("192.128.0.32"),
						DestinationPort: 51000,
						Protocol: "TCP",
					},
					{
						Timestamp: "",
						Source: net.ParseIP("192.0.0.15"),
						SourcePort: 80,
						Destination: net.ParseIP("192.128.0.32"),
						DestinationPort: 51000,
						Protocol: "UDP",
					},
					{
						Timestamp: "",
						Source: net.ParseIP("192.0.0.3"),
						SourcePort: 5000,
						Destination: net.ParseIP("192.128.0.32"),
						DestinationPort: 51000,
						Protocol: "UDP",
					},
					{
						Timestamp: "",
						Source: net.ParseIP("192.0.0.15"),
						SourcePort: 5000,
						Destination: net.ParseIP("192.128.0.32"),
						DestinationPort: 51000,
						Protocol: "TCP",
					},
				}

				detector := engine.DetectAttacks([]engine.Policy{
					{
						ID: "1",
						Name: "inspect Martin's laptop",
						IPMap: map[string]interface{}{"192.0.0.3":nil},
						Verdict: "INSPECT",
					},
					{
						ID: "2",
						Name: "Ignore certain ports",
						Ports: []engine.Port{{Start: 80, End: 90}},
						Verdict: "IGNORE",
					},
					{
						ID: "1",
						Name: "Inspect UDP",
						ProtocolMap: map[string]interface{}{"UDP":nil},
						Verdict: "INSPECT",
					},
				}, connections)

				assert.Equal(t, engine.DetectionResult{
					CleanCount: 4,
					NoMatchCount: 1,
					RuleCount: map[string]int{
						"inspect Martin's laptop":3,
						"Ignore certain ports": 3,
						"Inspect UDP": 2,
					},
					Suspicious: []engine.Connection{
						{
							Timestamp: "",
							Source: net.ParseIP("192.0.0.3"),
							SourcePort: 5000,
							Destination: net.ParseIP("192.128.0.32"),
							DestinationPort: 51000,
							Protocol: "TCP",
						},
						{
							Timestamp: "",
							Source: net.ParseIP("192.0.0.3"),
							SourcePort: 5000,
							Destination: net.ParseIP("192.128.0.32"),
							DestinationPort: 51000,
							Protocol: "UDP",
						},
					},
				}, detector)
			})
		})
	})
}