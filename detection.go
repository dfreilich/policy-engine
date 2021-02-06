package engine

// DetectionResult contains all information gathered during DetectAttacks
type DetectionResult struct {
	Suspicious []Connection
	RuleCount map[string]int
	NoMatchCount int
	CleanCount int
}

// DetectAttacks in a Connection slice, based on a Policy slice
// Parallelization could help performance, and could be taken care of by splitting the connection slice,
// and calling DetectAttacks with copies of the Policies, ultimately combining the DetectionResult responses.
func DetectAttacks(policies []Policy, conns []Connection) DetectionResult {
	result := &DetectionResult{
		RuleCount: map[string]int{},
	}

	runDetection(result, policies, conns)
	result.CleanCount = len(conns) - len(result.Suspicious)
	return *result
}

func runDetection(d *DetectionResult, policies []Policy, conns []Connection) {
	for _, conn := range conns {
		suspect := false
		ignore := false
		policyMatched := false
		for _, policy := range policies {
			if policy.Matches(conn) {
				policyMatched = true
				d.RuleCount[policy.Name] += 1
				if policy.Verdict == InspectVerdict {
					suspect = true
				} else if policy.Verdict == IgnoreVerdict {
					ignore = true
				}
			}
		}

		if !policyMatched {
			d.NoMatchCount += 1
		}

		if suspect && !ignore {
			d.Suspicious = append(d.Suspicious, conn)
		}
	}
}


