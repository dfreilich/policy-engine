package engine

import (
	"log"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var (
	// These are the default paths, used in the program. Users can override them, by providing arguments to the program.
	policyPath = filepath.Join("data", "policy.json")
	networkConnectionsPath = filepath.Join("data", "attacks.csv")
	outputPath = filepath.Join("out", "suspicious.csv")
)

// NewRunCommand creates a CLI for the engine
func NewRunCommand() *cobra.Command {
	cmd := &cobra.Command{
		Short: "Tool to detect network attacks, using a rule file",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runNetworkAnalysis(policyPath, networkConnectionsPath, outputPath)
		},
	}

	cmd.Flags().StringVarP(&policyPath, "policy", "p", policyPath, "Path to a valid JSON policy file")
	cmd.Flags().StringVarP(&networkConnectionsPath, "connections", "c", networkConnectionsPath, "Path to a valid connections csv file")
	cmd.Flags().StringVarP(&outputPath, "output", "o", outputPath, "Path for output suspicious CSV file")

	return cmd
}

func runNetworkAnalysis(policyPath, networkConnectionsPath, outputPath string) error {
	policyReader := PolicyReader{}
	policies, err := policyReader.Read(policyPath)
	if err != nil {
		return errors.Wrapf(err, "parsing policy file %s", policyPath)
	}

	connectionsRW := ConnectionsReadWriter{}
	connections, err := connectionsRW.Read(networkConnectionsPath)
	if err != nil{
		return errors.Wrapf(err, "parsing connections file %s", networkConnectionsPath)
	}

	results := DetectAttacks(policies, connections)

	log.Println("Successfully completed analyzing the connections.")
	log.Printf("\nResults:\n")
	log.Printf("* There were %d clean connections\n", results.CleanCount)
	log.Printf("* There were %d suspicious connections\n", len(results.Suspicious))
	log.Printf("* %d connection(s) didn't match any rule(s)\n", results.NoMatchCount)
	for key, val := range results.RuleCount {
		log.Printf("* Rule '%s' matched successfully with %d connections\n", key, val)
	}

	if len(results.Suspicious) == 0{
		log.Println("No suspicious connections were found.")
		log.Println("As a result, we won't write an output file.")
		return nil
	}

	return connectionsRW.Write(results.Suspicious, outputPath)
}


