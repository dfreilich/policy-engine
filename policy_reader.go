package engine

import (
	"encoding/json"
	"io/ioutil"
	"log"

	"github.com/pkg/errors"
)

// PolicyReader manages Policys, reading them in from a valid `policy.json` file.
// It is based on the Go ReadWriter pattern, but intentionally doesn't accept the path/file as an input to the struct
// creation, to make it similar to the ConnectionsReadWriter.
type PolicyReader struct {}

// This leaves the results from the json intentionally untyped, to make it more resilient to improper values.
type policyJson struct {
	ID        interface{}   `json:"id"`
	Name      interface{}   `json:"name"`
	IPs       []interface{} `json:"ips,omitempty"`
	Ports     []interface{}   `json:"ports,omitempty"`
	Protocols []interface{} `json:"protocols,omitempty"`
	Verdict   interface{}   `json:"verdict"`
}

// Read a `policy.json` file and returns a Policy slice
func (p PolicyReader) Read(path string) ([]Policy, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read policy file")
	}

	var policies []policyJson
	err = json.Unmarshal(content, &policies)
	if err != nil {
		log.Printf("Error unmarsheling the policy json")
	}

	return transformToPolicies(policies)
}

func transformToPolicies(polJson []policyJson) ([]Policy, error) {
	var policies []Policy

	for _, pol := range polJson {
		policies = append(policies, NewPolicy(pol))
	}

	return policies, nil
}


