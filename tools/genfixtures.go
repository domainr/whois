// +build ignore

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"code.google.com/p/go.net/idna"
)

var (
	v, quick    bool
	concurrency int
	zones       []string
	prefixes    []string
)

func init() {
	flag.BoolVar(&v, "v", false, "verbose output (to stderr)")
	flag.BoolVar(&quick, "quick", false, "Only work on a subset of zones")
	flag.IntVar(&concurrency, "concurrency", 8, "Set maximum number of concurrent requests")
}

func main() {
	flag.Parse()

	if err := main1(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main1() error {
	var err error
	zones, err = readLines("zones.txt")
	if err != nil {
		return err
	}
	prefixes, err = readLines("prefixes.txt")
	if err != nil {
		return err
	}

	// Quick for debugging?
	if quick {
		zones = zones[0:50]
	}

	// fmt.Println(strings.Join(zones, "\n"))
	// fmt.Println("\n\n-------------------\n\n")
	// fmt.Println(strings.Join(prefixes, "\n"))

	limiter := make(chan struct{}, concurrency) // semaphore to limit concurrency

	fmt.Fprintf(os.Stderr, "Querying whois for %d prefixes and %d zones\n", len(prefixes), len(zones))

	// Create 1 goroutine for each zone
	for _, zone := range zones {
		for _, prefix := range prefixes {
			go func(prefix, zone string) {
				limiter <- struct{}{} // acquire semaphore
				defer func() {        // release semaphore
					<-limiter
				}()

				fmt.Printf("%s.%s\n", prefix, zone)
			}(prefix, zone)
		}
	}

	return nil
}

var re = regexp.MustCompile("\\s+|#.+$")

func readLines(fn string) (out []string, err error) {
	fmt.Fprintf(os.Stderr, "Reading %s\n", fn)
	_, file, _, _ := runtime.Caller(0)
	buf, err := ioutil.ReadFile(filepath.Join(filepath.Dir(file), "../test/fixtures/", fn))
	if err != nil {
		return
	}
	s := strings.Trim(string(buf), "\n")
	lines := strings.Split(s, "\n")
	for _, line := range lines {
		line = re.ReplaceAllLiteralString(line, "")
		if line != "" {
			line, _ = idna.ToASCII(line)
			out = append(out, line)
		}
	}
	return
}
