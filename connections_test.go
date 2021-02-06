package engine_test

import (
	"net"
	"testing"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/assert"

	"github.com/dfreilich/guardicore-policy-engine"
)

func TestConnections(t *testing.T) {
	spec.Run(t, "Connections", testConnections, spec.Parallel(), spec.Report(report.Terminal{}))
}

func testConnections(t *testing.T, when spec.G, it spec.S) {
	when("#NewConnection", func() {
		it("creates a connection", func() {
			csv := []string{"1599665154.660434","192.0.0.2","5000","192.128.0.20","38038","TCP"}
			connection := engine.NewConnection(csv)
			assert.Equal(t, engine.Connection{
				Timestamp:       "1599665154.660434",
				Source:          net.ParseIP("192.0.0.2"),
				SourcePort:      5000,
				Destination:     net.ParseIP("192.128.0.20"),
				DestinationPort: 38038,
				Protocol:        "TCP",
			}, connection)
		})

		it("is resilient with improper values", func() {
			csv := []string{"1599665154.660434","192.0.0.2","not-a-number","192.128.0.20","38038","38383"}
			connection := engine.NewConnection(csv)
			assert.Equal(t, engine.Connection{
				Timestamp:       "1599665154.660434",
				Source:          net.ParseIP("192.0.0.2"),
				SourcePort:      0,
				Destination:     net.ParseIP("192.128.0.20"),
				DestinationPort: 38038,
				Protocol:        "38383",
			}, connection)
		})
	})
}