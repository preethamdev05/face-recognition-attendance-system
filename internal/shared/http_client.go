package shared

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// HTTPClient is a configured HTTP client for inter-service communication
type HTTPClient struct {
	client  *http.Client
	baseURL string
	headers map[string]string
}

// NewHTTPClient creates a new HTTP client
func NewHTTPClient(baseURL string, timeout time.Duration) *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
		},
		baseURL: baseURL,
		headers: make(map[string]string),
	}
}

// SetHeader adds a default header
func (c *HTTPClient) SetHeader(key, value string) {
	c.headers[key] = value
}

// Post makes a POST request with correlation ID propagation
func (c *HTTPClient) Post(ctx context.Context, path string, body interface{}, headers map[string]string) (*http.Response, error) {
	url := c.baseURL + path
	
	var bodyReader *bytes.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(jsonBody)
	} else {
		bodyReader = bytes.NewReader([]byte{})
	}
	
	req, err := http.NewRequestWithContext(ctx, "POST", url, bodyReader)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	// Propagate correlation ID
	cid := GetCorrelationID(ctx)
	if cid != "" {
		req.Header.Set("X-Correlation-ID", cid)
	}
	
	// Set default headers
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	
	// Set request-specific headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	
	return c.client.Do(req)
}

// Get makes a GET request with correlation ID propagation
func (c *HTTPClient) Get(ctx context.Context, path string, headers map[string]string) (*http.Response, error) {
	url := c.baseURL + path
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	// Propagate correlation ID
	cid := GetCorrelationID(ctx)
	if cid != "" {
		req.Header.Set("X-Correlation-ID", cid)
	}
	
	// Set default headers
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	
	// Set request-specific headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	
	return c.client.Do(req)
}
