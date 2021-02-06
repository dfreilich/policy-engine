// Package engine provides tools for reading policy and connection files, analyzing connections for attacks, and writing
// connections to an output file
package engine

import (
	"log"
	"net"
	"strconv"
)

// Connection defines a network connection.
type Connection struct {
	Timestamp string // Stored as a string, in order to conserve effort when saving back to a file
	Source net.IP
	SourcePort int
	Destination net.IP
	DestinationPort int
	Protocol string
}

// NewConnection takes a row of information from a CSV (represented by an array of strings), and returns the parsed Connection object.
func NewConnection(row []string) Connection {
	conn := Connection{
		Timestamp: row[0],
		Source: net.ParseIP(row[1]),
		Destination: net.ParseIP(row[3]),
		Protocol: row[5],
	}

	var err error
	if row[2] != "" {
		if conn.SourcePort, err = strconv.Atoi(row[2]); err != nil {
			// Printing an error, but not erroring out, to ensure it is resilient
			log.Printf("Invalid source port value %s found", row[2])
		}
	}

	if row[4] != "" {
		if conn.DestinationPort, err = strconv.Atoi(row[4]); err != nil {
			// Printing an error, but not erroring out, to ensure it is resilient
			log.Printf("Invalid destination port value %s found", row[4])
		}
	}

	return conn
}

func (c Connection) toCSV() []string{
	return []string{c.Timestamp, c.Source.String(), strconv.Itoa(c.SourcePort), c.Destination.String(), strconv.Itoa(c.DestinationPort), c.Protocol}
}

