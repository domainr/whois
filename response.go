package whois

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"code.google.com/p/go.net/html/charset"
	"code.google.com/p/go.text/encoding"
	"code.google.com/p/go.text/transform"
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
		FetchedAt: time.Now().UTC(),
		MediaType: "text/plain",
	}
}

// String returns the response body.
func (res *Response) String() string {
	r, err := res.Reader()
	if err != nil {
		return ""
	}
	body, err := ioutil.ReadAll(r)
	if err != nil {
		return ""
	}
	return string(body)
}

// Reader returns a new UTF-8 io.Reader for the response body.
func (res *Response) Reader() (io.Reader, error) {
	enc, err := res.Encoding()
	if err != nil {
		return nil, err
	}
	return transform.NewReader(bytes.NewReader(res.Body), enc.NewDecoder()), nil
}

// Encoding returns an Encoding for the response body.
func (res *Response) Encoding() (encoding.Encoding, error) {
	enc, _ := charset.Lookup(res.Charset)
	if enc == nil {
		return nil, errors.New("No encoding found for " + res.Charset)
	}
	return enc, nil
}

// DetectContentType detects and sets the response content type and charset.
func (res *Response) DetectContentType(ct string) {
	// Autodetect if not passed a Content-Type header
	if ct == "" {
		ct = http.DetectContentType(res.Body)
	}

	// Content type (e.g. text/plain or text/html)
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return
	}
	res.MediaType = mt
	res.DetectCharset()
}

// DetectCharset sets the charset field of the response to the best guess for
// the response body's character set.
func (res *Response) DetectCharset() {
	var certain bool

	// Detect via BOM or HTML media type.
	_, res.Charset, certain = charset.DetermineEncoding(res.Body, res.MediaType)
	if certain {
		return
	}

	// Detect via ICU and set if confidence is high enough.
	var det *chardet.Detector
	if strings.Contains(res.MediaType, "html") {
		det = chardet.NewHtmlDetector()
	} else {
		det = chardet.NewTextDetector()
	}
	r, err := det.DetectBest(res.Body)
	if err == nil && r.Confidence > 50 {
		_, res.Charset = charset.Lookup(r.Charset)
	}

	// fmt.Printf("Detected charset via go.net/html/charset: %s (%t)\n", cs1, ok1)
	// fmt.Printf("Detected charset via saintfish/chardet:   %s (%d)\n", cs2, r[0].Confidence)
}

// Checksum returns a hex-encoded SHA-1 checksum of the response Body.
func (res *Response) Checksum() string {
	h := sha1.New()
	h.Write(res.Body)
	return strings.ToLower(hex.EncodeToString(h.Sum(nil)))
}

// Header returns a stringproto header representing the response.
func (res *Response) Header() http.Header {
	h := make(http.Header)
	h.Set("Query", res.Query)
	h.Set("Host", res.Host)
	h.Set("Fetched-At", res.FetchedAt.Format(time.RFC3339))
	h.Set("Content-Type", res.ContentType())
	h.Set("Content-Length", strconv.Itoa(len(res.Body)))
	h.Set("Content-Checksum", res.Checksum())
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

// ReadMIME reads a MIME-formatted representation of the response into a Response.
func ReadMIME(r io.Reader) (*Response, error) {
	msg, err := mail.ReadMessage(r)
	if err != nil {
		return nil, err
	}
	h := msg.Header
	res := NewResponse(h.Get("Query"), h.Get("Host"))
	if res.Body, err = ioutil.ReadAll(io.LimitReader(msg.Body, DefaultReadLimit)); err != nil {
		return res, err
	}
	if res.FetchedAt, err = time.Parse(time.RFC3339, h.Get("Fetched-At")); err != nil {
		return res, err
	}
	if mt, params, err := mime.ParseMediaType(h.Get("Content-Type")); err != nil {
		return res, err
	} else {
		res.MediaType = mt
		res.Charset = params["charset"]
	}
	return res, nil
}
