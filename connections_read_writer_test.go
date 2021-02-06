package engine_test

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/assert"

	"github.com/dfreilich/guardicore-policy-engine"
)

func TestConnectionsReadWriter(t *testing.T) {
	spec.Run(t, "ConnectionsReadWriter", testConnectionsReadWriter, spec.Parallel(), spec.Report(report.Terminal{}))
}

func testConnectionsReadWriter(t *testing.T, when spec.G, it spec.S) {
	var connectionRW = engine.ConnectionsReadWriter{}

	when("#Read", func() {
		when("connections file doesn't exist", func() {
			it("returns a clear error", func() {
				_, err := connectionRW.Read(filepath.Join("/tmp", "path", "does-not-exist"))
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "failed to read connection file")
			})
		})

		when("empty connections file", func() {
			it("returns no connections", func() {
				connections, err := connectionRW.Read(filepath.Join(testdataPath, "empty_connections.csv"))
				assert.Nil(t, err)
				assert.Equal(t, len(connections), 0)
			})
		})

		when("faulty connections file", func() {
			it("doesn't error out, and returns the valid connections", func() {
				connections, err := connectionRW.Read(filepath.Join(testdataPath, "flawed_connections.csv"))
				assert.Nil(t, err)
				assert.Equal(t, len(connections), 223)
			})
		})

		when("full connections file", func() {
			it("returns all connections", func() {
				connections, err := connectionRW.Read(filepath.Join(testdataPath, "connections.csv"))
				assert.Nil(t, err)
				assert.Equal(t, len(connections), 223)
				assert.Equal(t, connections[0], engine.Connection{
					Timestamp: "1599665118.593452",
					Source: net.ParseIP("192.0.0.2"),
					SourcePort: 5000,
					Destination: net.ParseIP("192.128.0.32"),
					DestinationPort: 51000,
					Protocol: "TCP",
				})
			})
		})
	})
}