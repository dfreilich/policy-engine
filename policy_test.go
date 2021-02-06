package engine_test

import (
	"net"
	"testing"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/assert"

	"github.com/dfreilich/guardicore-policy-engine"
)

var testdataPath = "testdata"

func TestPolicy(t *testing.T) {
	spec.Run(t, "Policy", testPolicy, spec.Parallel(), spec.Report(report.Terminal{}))
}

func testPolicy(t *testing.T, when spec.G, it spec.S) {
	when("#Matches", func() {
		var (
			pol  engine.Policy
			conn engine.Connection
		)

		it.Before(func() {
			pol = engine.Policy{
				ID:      "some-id",
				Name:    "some-name",
				Verdict: engine.InspectVerdict,
			}

			conn = engine.Connection{
					Timestamp: "1599665118.593452",
					Source: net.ParseIP("192.0.0.3"),
					SourcePort: 5000,
					Destination: net.ParseIP("192.128.0.32"),
					DestinationPort: 51000,
					Protocol: "TCP",
			}
		})

		when("empty policy", func() {
			it("returns true", func() {
				assert.True(t, pol.Matches(conn))
			})
		})

		when("just matching ip", func() {
			it("matches source ip", func() {
				pol.IPMap = map[string]interface{}{"192.0.0.3":nil}
				assert.True(t, pol.Matches(conn))
			})

			it("matches destination ip", func() {
				pol.IPMap = map[string]interface{}{"192.128.0.32":nil}
				assert.True(t, pol.Matches(conn))
			})

			it("doesn't match when no ip matches", func() {
				pol.IPMap = map[string]interface{}{"192.125.023.32":nil}
				assert.False(t, pol.Matches(conn))
			})
		})

		when("just matching ports", func() {
			it("matches source port", func() {
				pol.Ports = []engine.Port{{Start: 4900, End: 5001}}
				assert.True(t, pol.Matches(conn))
			})

			it("matches destination port", func() {
				pol.Ports = []engine.Port{{Start: 50100, End: 51003}}
				assert.True(t, pol.Matches(conn))
			})
		})

		when("just matching protocols", func() {
			it("matches protocol", func() {
				pol.ProtocolMap = map[string]interface{}{"TCP":nil}
				assert.True(t, pol.Matches(conn))
			})
		})

		when("matches both ip and ports", func() {
			it("returns false if only satisfies one", func() {
				pol.IPMap = map[string]interface{}{"192.0.0.3":nil}
				pol.Ports = []engine.Port{{Start: 80, End: 90}}
				assert.False(t, pol.Matches(conn))
			})

			it("returns true if satisfies both on the same side", func() {
				pol.IPMap = map[string]interface{}{"192.0.0.3":nil}
				pol.Ports = []engine.Port{{Start: 5000, End: 5000}}
				assert.True(t, pol.Matches(conn))
			})

			it("returns true if satisfies both on the same side, and one on the same side", func() {
				conn.Destination = net.ParseIP("192.0.0.3")
				pol.IPMap = map[string]interface{}{"192.0.0.3":nil}
				pol.Ports = []engine.Port{{Start: 51000, End: 51000}}
				assert.True(t, pol.Matches(conn))
			})

			it("returns false if satisfies both, but on opposite sides", func() {
				pol.IPMap = map[string]interface{}{"192.0.0.3":nil}
				pol.Ports = []engine.Port{{Start: 50100, End: 51003}}
				assert.False(t, pol.Matches(conn))
			})
		})
	})
}