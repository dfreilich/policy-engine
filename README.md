# Policy Engine
This is a Policy Engine, written for Guardicore's Software Engineer Assessment

## Usage
To run the program, either build the binary (see [build](#building)), or just run:
```bash
$ go run cmd/main.go
```

The program has built in inputs (which can be seen in the `data` directory), but you can adjust the inputs by providing
flags to the program. The available flags are:
```bash
Flags:
  -c, --connections string   Path to a valid connections csv file (default "data/attacks.csv")
  -h, --help                 help for this command
  -o, --output string        Path for output suspicious CSV file (default "out/suspicious.csv")
  -p, --policy string        Path to a valid JSON policy file (default "data/policy.json")
```

For help, run:
```bash
$ go run cmd/main.go -h
```

## Building
To build the binary, run:
```bash
$ go build cmd/main.go -o out/engine
```

## Testing
To run the tests, run:
```bash
$ go test -v ./...
```

## Sample Output
The output of the program, given the default settings, is:
```bash
$  go run cmd/main.go
Successfully completed analyzing the connections.

Results:
* There were 3448926 clean connections
* There were 11186 suspicious connections
* 257e4195 connection(s) didn't match any rule(s)
* Rule 'ignore database DMZ' matched successfully with 16706 connections
* Rule 'ignore allowed ports' matched successfully with 769332 connections
* Rule 'ignore ICMP' matched successfully with 88693 connections
* Rule 'inspect SSH' matched successfully with 6824 connections
* Rule 'inspect Martin's laptop' matched successfully with 11267 connections
* Rule 'inspect DNS' matched successfully with 16 connections
Writing suspicious connections file to out/suspicious.csv
Successfully wrote file.
```

## Next Steps
Next steps for improving this project are:
  * Add caching for Connections, and report cache hit/miss rate
  * Add goroutines and split up the Connections slice, to help with scaling
  * Add better logging, and use a more expressive and colored logger, to have a better UX

## Prompt
Write a program which analyzes a log of network connections in CSV format downloaded from
TechCorp production web server.

The CSV provided has the following columns:
- “timestamp” - Connection time in epoch
- “source” - Source IP or MAC address
- “source_port” - Source port (when applicable)
- “destination” - Destination IP or MAC address
- “destination_port” - Destination port (when applicable)
- “protocol” - protocol (either “ICMP”, “TCP”, “UDP”, or “ARP”)

#### Policy engine features
1. The policy is based on a list of rules. These are provided in a JSON format, as described in the
documentation.
1. Each of the criteria are optional. If a criterion isn’t explicitly specified, it should match to any value.
1. IP or port criteria may be matched to either source or destination. However, when a rule specifies both, then they should both match on the same side.
1. The policy engine should analyze the connections against the rules in the order they are defined in the JSON. Once a connection has been matched against all necessary rules the engine should return the final verdict like so:
   - Has it matched any IGNORE rule? Return CLEAN.
   - Has it matched only INSPECT rules? Return SUSPICIOUS.
   - Has it matched no rules at all? Return CLEAN.
   
Clarification  
- Rule A defines only an IP criterion: `“ips”: [“10.0.0.1/32”]` &rarr; INSPECT
- Rule B defines only a Port criterion: `“ports”: [{“start”: 80, “end”: 90}]` &rarr; IGNORE
- Rule C defines both criteria: `“ips”: [“10.0.0.1/32”], “ports”: [{“start”: 80, “end”: 90}]` &rarr; INSPECT

Here are some examples of final verdicts according to which rules were matched:
- Connection only matching rule 1, is deemed SUSPICIOUS.
- Connection only matching rule 2, is deemed CLEAN.
- Connection matching rule 1 & 2, is deemed CLEAN.
- Connection matching rule 2 & 3, is deemed CLEAN.
- Connection matching rule 1 & 3, is deemed SUSPICIOUS.
- Connection matching no rules, is deemed CLEAN.

Note that you don’t necessarily need to analyze all the rules, since once a connection matches an
IGNORE rule it will always be deemed CLEAN.

#### Expected Output
Your engine should produce the following outputs. This list is prioritized, from most important, to
bonus.
1. **Must**: Count of how many connections were CLEAN, and how many were SUSPICIOUS
2. **Must**: Produce an output CSV with all SUSPICIOUS connections.
3. **Nice** to have: Count of how many connections matched successfully with each of the rules.
4. **Nice** to have: Count of how many connections didn’t match any rule.
5. **Bonus**: Cache already matched sessions (source, destination, ports, protocol), and report the
   cache hit/miss rates.

#### Implementation Instructions
1. You may implement in: Python, Golang, Java, Javascript, C#, C++.
   If you wish to implement in another language please inform us beforehand.
2. You may use any external library or framework.
3. Online searching is allowed and recommended.
4. If you are pressed for time and need to make sacrifices in functionality, let us know what
   cases are not covered or what limitations are imposed and how you would have improved it
   given more time.
5. Your script should be as efficient as possible - running more than 30min is not acceptable.
6. As in real life - your input file might have things you are having trouble reading. Your code
   should be resilient and not break in such cases.

#### Assessment Criteria
The goal of the assignment is to evaluate the coding skill. We will review your code as we review real code in our products, not as an “academic” code. These are the criteria we assess according to, in order of importance.
1. Correctness. We assess the submission contains and implements all the features correctly.
2. Resiliency. Being able to handle edge cases and errors without crashing.
3. Performance. Aim to reduce run time and resource consumption. Consider scalability.
4. Structure. Design your solution to follow object-oriented guidelines and structure.
5. Readability. Comment and annotate when required.

#### Shipping Directions
Please hand in:
- Source code.
- Compilation instructions. Including required dependencies and frameworks.
- Execution instructions. How to run and direct the program to a JSON file containing the
   rules and CSV file containing the connections.
- Expected output. What was the output on your setup, with the provided rules and
   connections.