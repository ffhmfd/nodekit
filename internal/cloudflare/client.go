package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ErrNotFound = errors.New("Cloudflare record not found")
var idRE = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}
type Record struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment,omitempty"`
}
type Client struct {
	Token   string
	BaseURL string
	HTTP    *http.Client
}
type APIError struct {
	Status int
	Codes  []int
}

func (e *APIError) Error() string {
	return fmt.Sprintf("Cloudflare HTTP %d, error codes %v", e.Status, e.Codes)
}
func Rejected(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.Status >= 400 && e.Status < 500 && e.Status != 408
}

func New(tokenFile string) (*Client, error) {
	info, err := os.Lstat(tokenFile)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0007 != 0 {
		return nil, errors.New("Token must be a restricted regular file")
	}
	b, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, err
	}
	token := strings.TrimSpace(string(b))
	if len(token) < 10 || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("invalid Cloudflare Token file")
	}
	return &Client{Token: token, BaseURL: "https://api.cloudflare.com/client/v4", HTTP: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Cloudflare redirect refused") }}}, nil
}

type envelope struct {
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result"`
	Errors  []struct {
		Code int `json:"code"`
	} `json:"errors"`
	Info struct {
		Pages int `json:"total_pages"`
	} `json:"result_info"`
}

func (c *Client) request(ctx context.Context, method, path string, body, out any) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var input io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		input = bytes.NewReader(b)
	}
	base := c.BaseURL
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, input)
	if err != nil {
		return 0, errors.New("invalid Cloudflare request")
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	}
	response, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, errors.New("Cloudflare request failed; check network connectivity")
	}
	defer response.Body.Close()
	if response.StatusCode == 404 {
		return 0, ErrNotFound
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(b) > 2<<20 {
		return 0, errors.New("invalid or oversized Cloudflare response")
	}
	var result envelope
	decodeErr := json.Unmarshal(b, &result)
	if response.StatusCode < 200 || response.StatusCode >= 300 || !result.Success {
		codes := []int{}
		for _, e := range result.Errors {
			codes = append(codes, e.Code)
		}
		return 0, &APIError{Status: response.StatusCode, Codes: codes}
	}
	if decodeErr != nil {
		return 0, errors.New("invalid Cloudflare response")
	}
	if out != nil {
		if err = json.Unmarshal(result.Result, out); err != nil {
			return 0, errors.New("invalid Cloudflare result")
		}
	}
	if result.Info.Pages > 1000 {
		return 0, errors.New("Cloudflare pagination limit exceeded")
	}
	return result.Info.Pages, nil
}

func (c *Client) Zones(ctx context.Context) ([]Zone, error) {
	var all []Zone
	for page := 1; page <= 1000; page++ {
		var part []Zone
		total, err := c.request(ctx, "GET", "/zones?per_page=50&page="+strconv.Itoa(page), nil, &part)
		if err != nil {
			return nil, err
		}
		all = append(all, part...)
		if page >= total || len(part) == 0 {
			return all, nil
		}
	}
	return nil, errors.New("Cloudflare pagination limit exceeded")
}
func recordPath(zone, id string) (string, error) {
	if !idRE.MatchString(zone) || (id != "" && !idRE.MatchString(id)) {
		return "", errors.New("invalid Cloudflare resource ID")
	}
	p := "/zones/" + zone + "/dns_records"
	if id != "" {
		p += "/" + id
	}
	return p, nil
}
func (c *Client) Records(ctx context.Context, zone, name string) ([]Record, error) {
	path, err := recordPath(zone, "")
	if err != nil {
		return nil, err
	}
	var all []Record
	for page := 1; page <= 1000; page++ {
		var part []Record
		total, err := c.request(ctx, "GET", path+"?name="+url.QueryEscape(name)+"&per_page=100&page="+strconv.Itoa(page), nil, &part)
		if err != nil {
			return nil, err
		}
		all = append(all, part...)
		if page >= total || len(part) == 0 {
			return all, nil
		}
	}
	return nil, errors.New("Cloudflare pagination limit exceeded")
}
func (c *Client) Get(ctx context.Context, zone, id string) (Record, error) {
	var out Record
	path, err := recordPath(zone, id)
	if err != nil || id == "" {
		return out, errors.New("invalid Cloudflare record ID")
	}
	_, err = c.request(ctx, "GET", path, nil, &out)
	return out, err
}
func (c *Client) Create(ctx context.Context, zone string, r Record) (Record, error) {
	var out Record
	path, err := recordPath(zone, "")
	if err != nil {
		return out, err
	}
	r.ID = ""
	_, err = c.request(ctx, "POST", path, r, &out)
	return out, err
}
func (c *Client) Update(ctx context.Context, zone string, r Record) (Record, error) {
	var out Record
	path, err := recordPath(zone, r.ID)
	if err != nil || r.ID == "" {
		return out, errors.New("invalid Cloudflare record ID")
	}
	r.ID = ""
	_, err = c.request(ctx, "PUT", path, r, &out)
	return out, err
}
func (c *Client) Delete(ctx context.Context, zone, id string) error {
	path, err := recordPath(zone, id)
	if err != nil || id == "" {
		return errors.New("invalid Cloudflare record ID")
	}
	_, err = c.request(ctx, "DELETE", path, nil, nil)
	return err
}
