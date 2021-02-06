package engine_test

import (
	"path/filepath"
	"testing"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/assert"

	"github.com/dfreilich/guardicore-policy-engine"
)

func TestPolicyReader(t *testing.T) {
	spec.Run(t, "PolicyReader", testPolicyReader, spec.Parallel(), spec.Report(report.Terminal{}))
}

func testPolicyReader(t *testing.T, when spec.G, it spec.S) {
	var policyReader = engine.PolicyReader{}
	when("#Read", func() {
		when("policy file doesn't exist", func() {
			it("returns a clear error", func() {
				_, err := policyReader.Read(filepath.Join("/tmp", "path", "does-not-exist"))
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "failed to read policy file")
			})
		})

		when("empty policy file", func() {
			it("returns no policies", func() {
				policies, err := policyReader.Read(filepath.Join(testdataPath, "empty_policy.json"))
				assert.Nil(t, err)
				assert.Equal(t, len(policies), 0)
			})
		})

		when("flawed policy file", func() {
			it("doesn't error out", func() {
				policies, err := policyReader.Read(filepath.Join(testdataPath, "flawed_policy.json"))
				assert.Nil(t, err)
				assert.Equal(t, len(policies), 7)
				assert.Equal(t, []engine.Policy{
					{
						ID: "689c5f1a-f2b1-11ea-a4c8-0050569de26b",
						Name: "ignore ICMP",
						ProtocolMap: map[string]interface{}{"ICMP":nil},
						Verdict: "IGNORE",
					},
					{
						ID: "1234",
						Name: "ignore loopback",
						IPMap: map[string]interface{}{"127.0.0.0": nil},
						Verdict: "IGNORE",
					},
					{
						ID: "3793072e-f2b2-11ea-b82e-0050569de26b",
						Name: "inspect SSH",
						Verdict: "INSPECT",
					},
					{
						ID: "aff46334-f2b2-11ea-a6f5-0050569de26b",
						Name: "ignore database DMZ",
						IPMap: map[string]interface{}{"192.128.0.0":nil},
						Verdict: "IGNORE",
					},
					{
						ID: "0b6f4a12-f2b3-11ea-80c0-0050569de26b",
						Name: "ignore allowed ports",
						Verdict: "IGNORE",
					},
					{
						ID: "c36049aa-f2b3-11ea-aa02-0050569de26b",
						Name: "inspect Martin's laptop",
						IPMap: map[string]interface{}{"192.0.0.3":nil},
						Verdict: "INSPECT",
					},
					{
						ID: "eca4acba-f2b4-11ea-852a-0050569de26b",
						Name: "inspect DNS",
						ProtocolMap: map[string]interface{}{"UDP":nil},
						IPMap: map[string]interface{}{"10.0.0.8":nil},
						Ports: []engine.Port{{
							Start: 53,
							End: 53,
						}},
						Verdict: "INSPECT",
					},
				}, policies)
			})
		})

		when("policy file", func() {
			it("returns list of policies", func() {
				policies, err := policyReader.Read(filepath.Join(testdataPath, "policy.json"))
				assert.Nil(t, err)
				assert.Equal(t,  7, len(policies))
				assert.Equal(t, []engine.Policy{
					{
						ID: "689c5f1a-f2b1-11ea-a4c8-0050569de26b",
						Name: "ignore ICMP",
						ProtocolMap: map[string]interface{}{"ICMP":nil},
						Verdict: "IGNORE",
					},
					{
						ID: "c7167eba-f2af-11ea-a947-0050569dae70",
						Name: "ignore loopback",
						IPMap: map[string]interface{}{"127.0.0.0": nil},
						Verdict: "IGNORE",
					},
					{
						ID: "3793072e-f2b2-11ea-b82e-0050569de26b",
						Name: "inspect SSH",
						Ports: []engine.Port{{
							Start: 22,
							End: 22,
						}},
						Verdict: "INSPECT",
					},
					{
						ID: "aff46334-f2b2-11ea-a6f5-0050569de26b",
						Name: "ignore database DMZ",
						IPMap: map[string]interface{}{"192.128.0.0":nil},
						Verdict: "IGNORE",
					},
					{
						ID: "0b6f4a12-f2b3-11ea-80c0-0050569de26b",
						Name: "ignore allowed ports",
						Ports: []engine.Port{{
							Start: 50,
							End: 150,
						}},
						Verdict: "IGNORE",
					},
					{
						ID: "c36049aa-f2b3-11ea-aa02-0050569de26b",
						Name: "inspect Martin's laptop",
						IPMap: map[string]interface{}{"192.0.0.3":nil},
						Verdict: "INSPECT",
					},
					{
						ID: "eca4acba-f2b4-11ea-852a-0050569de26b",
						Name: "inspect DNS",
						ProtocolMap: map[string]interface{}{"UDP":nil},
						IPMap: map[string]interface{}{"10.0.0.8":nil},
						Ports: []engine.Port{{
							Start: 53,
							End: 53,
						}},
						Verdict: "INSPECT",
					},
				}, policies)
			})
		})
	})
}
