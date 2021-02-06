package engine

import (
	"bytes"
	"log"
	"os"
	"testing"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestIntegration(t *testing.T) {
	spec.Run(t, "Integration", testIntegration, spec.Parallel(), spec.Report(report.Terminal{}))
}

func testIntegration(t *testing.T, when spec.G, it spec.S) {
	var (
		cmd *cobra.Command
		outBuf bytes.Buffer
	)

	it.Before(func() {
		cmd = NewRunCommand()
		log.SetOutput(&outBuf)
		cmd.SetOut(&outBuf)
		cmd.SetErr(&outBuf)
	})

	it.After(func() {
		assert.Nil(t, os.RemoveAll("out"))
	})

	when("-h", func() {
		it("prints usage", func() {
			cmd.SetArgs([]string{"-h"})
			assert.Nil(t, cmd.Execute())
			assert.Contains(t, outBuf.String(), "Usage:")
		})
	})

	when("default inputs", func() {
		it.After(func() {
			assert.Nil(t, os.Remove(outputPath))
		})

		it("works", func() {
			cmd.SetArgs([]string{})
			assert.Nil(t, cmd.Execute())
			assert.FileExists(t, outputPath)
			output := outBuf.String()
			for _, line := range []string{
				"3448926 clean","11186 suspicious", "2574195 connection(s) didn't match",
				"88693", "6824", "11186", "16706", "769332"} {
				assert.Contains(t, output, line)
			}
		})
	})
}