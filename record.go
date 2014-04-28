package whois

import (
	"errors"
)

// Record represents an individual whois record
type Record interface {
	Query() string
	URL() string
	ContentType() string
	Encoding() string
	Body() []byte
	String() string
	Parse() error
}

type recordFields struct {
	query       string
	url         string
	contentType string
	encoding    string
	body        []byte
}

func (record *recordFields) Query() string { return record.query }
func (record *recordFields) URL() string { return record.url }
func (record *recordFields) ContentType() string { return record.contentType }
func (record *recordFields) Encoding() string { return record.encoding }
func (record *recordFields) Body() []byte { return record.body }
func (record *recordFields) String() string { return string(record.body) }
func (record *recordFields) Parse() error { return errors.New("Parse() method not implemented.") }

type baseRecord struct {
	recordFields
}

type nrRecord baseRecord

func (record *nrRecord) Parse() error {
	return nil
}

func RecordStore() Record {
	record := &nrRecord{recordFields{query: "domai.nr"}}
	return record
}
