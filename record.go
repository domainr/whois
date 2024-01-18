package whois

import (
	"regexp"
	"strings"
)

// Record represents a parsed whois response.
type Record struct {
	DomainName          string
	RegistryDomainID    string
	Registrar           string
	UpdatedDate         string
	CreationDate        string
	ExpiryDate          string
	Status              []string
	NameServers         []string
	DNSSEC              string
	WhoisDatabaseUpdate string
}

// ParseResponse parses a whois.Response and returns a parsed Record.
func ParseResponse(response *Response) *Record {
	record := &Record{}

	// Define regular expressions for each field
	reDomainName := regexp.MustCompile(`Domain Name: (.+)`)
	reRegistryDomainID := regexp.MustCompile(`Registry Domain ID: (.+)`)
	reRegistrar := regexp.MustCompile(`Registrar: (.+)`)
	reUpdatedDate := regexp.MustCompile(`Updated Date: (.+)`)
	reCreationDate := regexp.MustCompile(`Creation Date: (.+)`)
	reExpiryDate := regexp.MustCompile(`Registry Expiry Date: (.+)`)
	reStatus := regexp.MustCompile(`Domain Status: (.+)`)
	reNameServer := regexp.MustCompile(`Name Server: (.+)`)
	reDNSSEC := regexp.MustCompile(`DNSSEC: (.+)`)
	reWhoisUpdate := regexp.MustCompile(`Last update of whois database: (.+)`)

	// Split the response into lines
	lines := strings.Split(string(response.Body), "\n")

	// Loop through each line and match the regular expressions
	for _, line := range lines {
		if matches := reDomainName.FindStringSubmatch(line); matches != nil {
			record.DomainName = matches[1]
		} else if matches := reRegistryDomainID.FindStringSubmatch(line); matches != nil {
			record.RegistryDomainID = matches[1]
		} else if matches := reRegistrar.FindStringSubmatch(line); matches != nil {
			record.Registrar = matches[1]
		} else if matches := reUpdatedDate.FindStringSubmatch(line); matches != nil {
			record.UpdatedDate = matches[1]
		} else if matches := reCreationDate.FindStringSubmatch(line); matches != nil {
			record.CreationDate = matches[1]
		} else if matches := reExpiryDate.FindStringSubmatch(line); matches != nil {
			record.ExpiryDate = matches[1]
		} else if matches := reStatus.FindAllStringSubmatch(line, -1); matches != nil {
			for _, match := range matches {
				record.Status = append(record.Status, match[1])
			}
		} else if matches := reNameServer.FindAllStringSubmatch(line, -1); matches != nil {
			for _, match := range matches {
				record.NameServers = append(record.NameServers, match[1])
			}
		} else if matches := reDNSSEC.FindStringSubmatch(line); matches != nil {
			record.DNSSEC = matches[1]
		} else if matches := reWhoisUpdate.FindStringSubmatch(line); matches != nil {
			record.WhoisDatabaseUpdate = matches[1]
		}
	}

	return record
}
