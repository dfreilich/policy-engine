package engine

import (
	"fmt"
	"log"
	"net"
	"strconv"
)

// Policy contains information about a network policy, and is matched against a Connection to see whether it matches
type Policy struct {
	ID        string
	Name      string
	IPMap	  map[string]interface{}
	Ports     []Port
	ProtocolMap map[string]interface{}
	Verdict   string
}

// Port defines a range of port values
type Port struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

var (
	IgnoreVerdict = "IGNORE"
	InspectVerdict = "INSPECT"
)

// NewPolicy accepts a policyJson, and parses it to form a Policy struct
func NewPolicy(policyJson policyJson) Policy {
	newPol := Policy{
		// Uses fmt.Sprintf to stringify the `interface{}` they are currently, without worrying about casting
		ID:        fmt.Sprintf("%v", policyJson.ID),
		Name:      fmt.Sprintf("%v", policyJson.Name),
		Verdict:   fmt.Sprintf("%v", policyJson.Verdict),
	}

	for _, ip := range policyJson.IPs {
		// This allows us to simplify the IP, from `192.0.0.0/32` to `192.0.0.0`, without doing manual processing
		parsedIP, _, err := net.ParseCIDR(fmt.Sprintf("%v", ip))
		if err != nil {
			log.Printf("Improper policy IP %s found \n", ip)
			continue
		}

		if newPol.IPMap == nil {
			newPol.IPMap = make(map[string]interface{})
		}
		if parsedIP != nil {
			newPol.IPMap[parsedIP.String()] = nil
		}
	}

	for _, protocol := range policyJson.Protocols {
		if newPol.ProtocolMap == nil {
			newPol.ProtocolMap = make(map[string]interface{})
		}
		newPol.ProtocolMap[fmt.Sprintf("%v", protocol)] = nil
	}

	for _, portRange := range policyJson.Ports {
		portMap, ok := portRange.(map[string]interface{})
		if ok {
			start, startOk := portMap["start"]
			startInt, startErr := strconv.Atoi(fmt.Sprintf("%v", start))
			end, endOk := portMap["end"]
			endInt, endErr := strconv.Atoi(fmt.Sprintf("%v", end))
			// This protects to ensure we don't have infinite ranges, because of an error parsing a value
			if startOk && endOk && startErr == nil && endErr == nil {
				newPol.Ports = append(newPol.Ports, Port{
					Start: startInt,
					End:   endInt,
				})
			} else {
				log.Printf("Improper policy port range %+v found \n", portMap)
			}
		}
	}
	return newPol
}

// Matches a Policy against a Connection, returning true if the Connection matches all set elements of the Policy
func (p Policy) Matches(conn Connection) bool {
	matchIP := p.IPMap == nil
	sourceIPFound,destIPFound := false, false
	// Separately handles both source and destination, because both could match the IP map
	if _, ok := p.IPMap[conn.Source.String()]; ok  {
		sourceIPFound = true
		matchIP = true
	}
	if _, ok := p.IPMap[conn.Destination.String()]; ok {
		destIPFound = true
		matchIP = true
	}

	matchPort := p.Ports == nil
	for _, portRange := range p.Ports {
		// Separately handles both source and destination port, because both could match
		if conn.SourcePort >= portRange.Start && conn.SourcePort <= portRange.End {
			if p.IPMap == nil || sourceIPFound {
				matchPort = true
				break
			}
		}
		if conn.DestinationPort >= portRange.Start && conn.DestinationPort <= portRange.End {
			if p.IPMap == nil  || destIPFound {
				matchPort = true
				break
			}
		}
	}

	matchProtocol := p.ProtocolMap == nil
	if _, ok := p.ProtocolMap[conn.Protocol]; ok {
		matchProtocol = true
	}

	return matchIP && matchPort && matchProtocol
}