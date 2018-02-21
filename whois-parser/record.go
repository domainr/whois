package parser

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Status represents ICANN EPP status code that are
// specified in https://icann.org/epp
type Status uint32

// ParseStatusString returns Status of the given string
func ParseStatusString(name string) Status {

	// improve cross compatibility for "[name] [url]" format
	if spacePos := strings.Index(name, " "); spacePos > 0 {
		name = name[:spacePos]
	}

	switch name {

	// Server Status Codes are Set by Your Domain's Registry
	case "addPeriod":
		return StatusAddPeriod
	case "autoRenewPeriod":
		return StatusAutoRenewPeriod
	case "inactive":
		return StatusInactive
	case "ok":
		return StatusOK
	case "pendingCreate":
		return StatusPendingCreate
	case "pendingDelete":
		return StatusPendingDelete
	case "pendingRenew":
		return StatusPendingRenew
	case "pendingRestore":
		return StatusPendingRestore
	case "pendingTransfer":
		return StatusPendingTransfer
	case "pendingUpdate":
		return StatusPendingUpdate
	case "redemptionPeriod":
		return StatusRedemptionPeriod
	case "renewPeriod":
		return StatusRenewPeriod
	case "serverDeleteProhibited":
		return StatusServerDeleteProhibited
	case "serverHold":
		return StatusServerHold
	case "serverRenewProhibited":
		return StatusServerRenewProhibited
	case "serverTransferProhibited":
		return StatusServerTransferProhibited
	case "serverUpdateProhibited":
		return StatusServerUpdateProhibited
	case "transferPeriod":
		return StatusTransferPeriod

	// Client Status Codes are Set by Your Domain's Registrar
	case "clientDeleteProhibited":
		return StatusClientDeleteProhibited
	case "clientHold":
		return StatusClientHold
	case "clientRenewProhibited":
		return StatusClientRenewProhibited
	case "clientTransferProhibited":
		return StatusClientTransferProhibited
	case "clientUpdateProhibited":
		return StatusClientUpdateProhibited

	// status is unidentified
	default:
		return StatusUnknown
	}
}

// String implements fmt.Stringer
func (c Status) String() string {
	switch c {

	// Server Status Codes are Set by Your Domain's Registry
	case StatusAddPeriod:
		return "addPeriod"
	case StatusAutoRenewPeriod:
		return "autoRenewPeriod"
	case StatusInactive:
		return "inactive"
	case StatusOK:
		return "ok"
	case StatusPendingCreate:
		return "pendingCreate"
	case StatusPendingDelete:
		return "pendingDelete"
	case StatusPendingRenew:
		return "pendingRenew"
	case StatusPendingRestore:
		return "pendingRestore"
	case StatusPendingTransfer:
		return "pendingTransfer"
	case StatusPendingUpdate:
		return "pendingUpdate"
	case StatusRedemptionPeriod:
		return "redemptionPeriod"
	case StatusRenewPeriod:
		return "renewPeriod"
	case StatusServerDeleteProhibited:
		return "serverDeleteProhibited"
	case StatusServerHold:
		return "serverHold"
	case StatusServerRenewProhibited:
		return "serverRenewProhibited"
	case StatusServerTransferProhibited:
		return "serverTransferProhibited"
	case StatusServerUpdateProhibited:
		return "serverUpdateProhibited"
	case StatusTransferPeriod:
		return "transferPeriod"

	// Client Status Codes are Set by Your Domain's Registrar
	case StatusClientDeleteProhibited:
		return "clientDeleteProhibited"
	case StatusClientHold:
		return "clientHold"
	case StatusClientRenewProhibited:
		return "clientRenewProhibited"
	case StatusClientTransferProhibited:
		return "clientTransferProhibited"
	case StatusClientUpdateProhibited:
		return "clientUpdateProhibited"

	// empty status, default value of Status type
	case StatusEmpty:
		return "empty"

	// unknown status in parse process
	case StatusUnknown:
		return "unknown"

	// parse all bits and join the string with "|"
	default:
		status := make([]string, 0, 32)
		for s, pos := c>>1, uint(1); s != 0; s, pos = s>>1, pos+1 {
			if s&1 != 0 {
				status = append(status, Status(1<<pos).String())
			}
		}
		return strings.Join(status, "|")
	}
}

// GoString implements fmt.GoStringer
func (c Status) GoString() string {
	return fmt.Sprintf("Status(%s)", c.String())
}

// Has test if this status includes the given status(s)
func (c Status) Has(s Status) bool {
	// always return false if c or s is unknown
	if c < StatusAddPeriod ||
		s < StatusAddPeriod ||
		c > StatusClientUpdateProhibited ||
		s > StatusClientUpdateProhibited {
		return false
	}
	return c&s == s
}

// Represents status that are specified in
// https://icann.org/epp
const (
	StatusEmpty Status = 0

	// Server Status Codes are Set by Your Domain's Registry
	StatusAddPeriod Status = 1 << iota
	StatusAutoRenewPeriod
	StatusInactive
	StatusOK
	StatusPendingCreate
	StatusPendingDelete
	StatusPendingRenew
	StatusPendingRestore
	StatusPendingTransfer
	StatusPendingUpdate
	StatusRedemptionPeriod
	StatusRenewPeriod
	StatusServerDeleteProhibited
	StatusServerHold
	StatusServerRenewProhibited
	StatusServerTransferProhibited
	StatusServerUpdateProhibited
	StatusTransferPeriod

	// Client Status Codes are Set by Your Domain's Registrar
	StatusClientDeleteProhibited
	StatusClientHold
	StatusClientRenewProhibited
	StatusClientTransferProhibited
	StatusClientUpdateProhibited

	// Unknown status
	StatusUnknown
)

// DNSSECState represents possible values in DNSSEC field
type DNSSECState int

// ParseDNSSECState parse the given string into DNSSECState
func ParseDNSSECState(str string) (s DNSSECState) {
	if str == "signedDelegation" {
		return DNSSECSignedDelegation
	}
	if str == "unsigned" {
		return DNSSECUnsigned
	}
	return
}

// String implements fmt.Stringer
func (s DNSSECState) String() string {
	switch s {
	case DNSSECSignedDelegation:
		return "signedDelegation"
	case DNSSECUnsigned:
		return "unsigned"
	}
	return "invalid"
}

// GoString implements fmt.GoStringer
func (s DNSSECState) GoString() string {
	return fmt.Sprintf("DNSSEC(%s)", s.String())
}

// possible DNSSECState values
const (
	_ DNSSECState = iota
	DNSSECSignedDelegation
	DNSSECUnsigned
)

// Contact represents information about Registrant, Admin or
// Tech information entry
type Contact struct {
	RegistryID    string
	Name          string
	Organization  string
	Street        string
	City          string
	StateProvince string
	PostalCode    string
	Country       string
	Phone         string
	PhoneExt      string
	Fax           string
	FaxExt        string
	Email         string
}

// Registrar represents the information
// about a domain registrar
type Registrar struct {
	Name                string
	WHOISServer         string
	URL                 string
	RegistrationExpires time.Time
	IANAID              string
	AbuseContactEmail   string
	AbuseContactPhone   string
}

// Record represents a parsed whois response.
type Record struct {
	// raw parsed key-value pairs
	Values url.Values

	// parsed values from key-value pairs
	DomainName   string
	RegistryID   string
	Registrar    Registrar
	Reseller     string
	Updated      time.Time
	Created      time.Time
	NameServers  []string
	DomainStatus Status
	Registrant   Contact
	Admin        Contact
	Tech         Contact
	DNSSEC       DNSSECState

	// legal disclaimer string at the end of record
	Disclaimer string
}
