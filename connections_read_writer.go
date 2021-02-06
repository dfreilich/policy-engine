package engine

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// ConnectionsReadWriter manages Connections, reading them in from a valid .csv file, and writing to a .csv file.
// It is based on the Go ReadWriter pattern, but intentionally doesn't accept the path/file as an input to the struct
// creation, to make it clear that it can read and write to separate locations.
type ConnectionsReadWriter struct {}

var headerRow = []string{"timestamp","source","source_port","destination","destination_port","protocol"}

// Read reads a connections `.csv` file, and returns a Connection slice
func (c ConnectionsReadWriter) Read(path string) ([]Connection, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read connection file")
	}
	defer f.Close()

	reader := csv.NewReader(f)
	var connections []Connection
	for {
		row, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			break
		//	Header row, if exists, isn't a valid Connection
		} else if row[0] == headerRow[0] {
			continue
		}

		connections = append(connections, NewConnection(row))
	}

	return connections, err
}

// Write a Connection slice to the output path
func (c ConnectionsReadWriter) Write(connections []Connection, path string) error {
	fmt.Printf("Writing suspicious connections file to %s\n", path)

	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return errors.Wrapf(err, "creating directory %s", filepath.Dir(path))
	}

	file, err := os.Create(path)
	if err != nil {
		return errors.Wrapf(err, "creating file %s", file.Name())
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err = writer.Write(headerRow); err != nil {
		return errors.Wrap(err, "writing header to file")
	}
	for _, value := range connections {
		if err = writer.Write(value.toCSV()); err != nil {
			return errors.Wrapf(err, "writing value %+v to file", value)
		}
	}

	log.Println("Successfully wrote file.")
	return nil
}


