package whois

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/saintfish/chardet"
)

// Response represents a whois response from a server.
type Response struct {
	Query     string
	Host      string
	FetchedAt time.Time
	MediaType string
	Charset   string
	Body      []byte
}

// NewResponse initializes a new whois response.
func NewResponse(query, host string) *Response {
	return &Response{
		Query:     query,
		Host:      host,
		FetchedAt: time.Now(),
	}
}

// String returns the response body.
func (res *Response) String() string {
	return string(res.Body)
}

// DetectContentType detects and sets the response content type and charset.
func (res *Response) DetectContentType(mt string) {
	// Sensible defaults
	res.MediaType = "text/plain"
	res.Charset = "utf-8"

	// Autodetect if not passed a Content-Type header
	if mt == "" {
		mt = http.DetectContentType(res.Body)
	}

	// Content type (e.g. text/plan or text/html)
	mt, params, err := mime.ParseMediaType(mt)
	if err != nil {
		return
	}
	res.MediaType = mt

	// Character set (e.g. utf-8)
	cs, ok := params["charset"]
	if ok {
		res.Charset = cs
	}
	res.DetectCharset()
}

// DetectCharset returns best guess for the reesponse body character set.
func (res *Response) DetectCharset() {
	var det *chardet.Detector
	if strings.Contains(res.MediaType, "html") {
		det = chardet.NewHtmlDetector()
	} else {
		det = chardet.NewTextDetector()
	}
	r, err := det.DetectAll(res.Body)
	if err != nil || len(r) == 0 {
		return
	}
	res.Charset = r[0].Charset
	fmt.Printf("%+v\n\n", r)
}

// Header returns a stringproto header representing the response.
func (res *Response) Header() http.Header {
	h := make(http.Header)
	h.Set("Query", res.Query)
	h.Set("Host", res.Host)
	h.Set("Fetched-At", res.FetchedAt.Format(time.RFC3339))
	h.Set("Content-Type", res.ContentType())
	h.Set("Content-Length", strconv.Itoa(len(res.Body)))
	return h
}

// ContentType returns an RFC 2045 compatible internet media type string.
func (res *Response) ContentType() string {
	return mime.FormatMediaType(res.MediaType, map[string]string{"charset": res.Charset})
}

// WriteMIME writes a MIME-formatted representation of the response to an io.Writer.
func (res *Response) WriteMIME(w io.Writer) error {
	io.WriteString(w, "MIME-Version: 1.0\r\n")
	err := res.Header().Write(w)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, "\r\n")
	if err != nil {
		return err
	}
	_, err = w.Write(res.Body)
	if err != nil {
		return err
	}
	return nil
}
