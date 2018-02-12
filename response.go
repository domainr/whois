package whois

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/saintfish/chardet"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding"
	"golang.org/x/text/transform"
)

// Response represents a whois response from a server.
type Response struct {
	// Query and Host are copied from the Request.
	Query string
	Host  string

	// FetchedAt is the date and time the response was fetched from the server.
	FetchedAt time.Time

	// MediaType and Charset hold the MIME-type and character set of the response body.
	MediaType string
	Charset   string

	// Body contains the raw bytes of the network response (minus HTTP headers).
	Body []byte
}

// NewResponse initializes a new whois response.
func NewResponse(query, host string) *Response {
	return &Response{
		Query:     query,
		Host:      host,
		FetchedAt: time.Now().UTC(),
		MediaType: "text/plain",
		Charset:   "utf-8",
	}
}

// Adapter returns an appropriate Adapter for the Response.
func (res *Response) Adapter() Adapter {
	return adapterFor(res.Host)
}

// String returns a string representation of the response text.
// Returns an empty string if an error occurs.
func (res *Response) String() string {
	text, err := res.Text()
	if err != nil {
		return ""
	}
	return string(text)
}

// Text returns the UTF-8 text content from the response body
// or any errors that occur while decoding.
func (res *Response) Text() ([]byte, error) {
	return res.Adapter().Text(res)
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
		return nil, fmt.Errorf("no encoding found for %s", res.Charset)
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
	mt, params, err := mime.ParseMediaType(ct)
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
	// Detect via BOM / HTML meta tag
	_, cs1, ok1 := charset.DetermineEncoding(res.Body, res.MediaType)

	// Detect via ICU
	cs2, ok2, html := "", false, false
	var det *chardet.Detector
	if strings.Contains(res.MediaType, "html") || true {
		det = chardet.NewHtmlDetector()
		html = true
	} else {
		det = chardet.NewTextDetector()
	}
	r, err := det.DetectAll(res.Body)
	if err == nil && len(r) > 0 {
		cs2 = strings.ToLower(r[0].Charset)
		ok2 = r[0].Confidence > 50
	}

	// Prefer charset if HTML, otherwise ICU
	if !ok2 && (ok1 || html) {
		res.Charset = cs1
	} else {
		res.Charset = cs2
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
	if res.Body, err = ioutil.ReadAll(msg.Body); err != nil {
		return res, err
	}
	if res.FetchedAt, err = time.Parse(time.RFC3339, h.Get("Fetched-At")); err != nil {
		return res, err
	}
	mt, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil {
		return res, err
	}
	res.MediaType = mt
	res.Charset = params["charset"]
	return res, nil
}

// ReadMIMEFile opens and reads a response MIME file at path.
// Returns any errors.
func ReadMIMEFile(path string) (*Response, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadMIME(f)
}
