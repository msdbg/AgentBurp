package models

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Request struct {
	ID          string   `json:"id"`
	ProjectID   string   `json:"project_id"`
	Source      string   `json:"source"`
	Method      string   `json:"method"`
	URL         string   `json:"url"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Scheme      string   `json:"scheme"`
	Path        string   `json:"path"`
	QueryString string   `json:"query_string"`
	Headers     []Header `json:"headers"`
	BodyHash    string   `json:"body_hash,omitempty"`
	BodySize    int      `json:"body_size_bytes"`
	SessionID   string   `json:"session_id,omitempty"`
	EndpointID  string   `json:"endpoint_id,omitempty"`
	CreatedAt   string   `json:"created_at"`
	Note        string   `json:"note,omitempty"`
	Body        []byte   `json:"body,omitempty"`
	Truncated   bool     `json:"truncated,omitempty"`
}

type Response struct {
	ID            string   `json:"id"`
	RequestID     string   `json:"request_id"`
	StatusCode    int      `json:"status_code"`
	Reason        string   `json:"reason"`
	Headers       []Header `json:"headers"`
	BodyHash      string   `json:"body_hash,omitempty"`
	BodySize      int      `json:"body_size_bytes"`
	ContentType   string   `json:"content_type"`
	TimeMs        int64    `json:"time_ms"`
	RedirectChain []string `json:"redirect_chain,omitempty"`
	CreatedAt     string   `json:"created_at"`
	Body          []byte   `json:"body,omitempty"`
	Truncated     bool     `json:"truncated,omitempty"`
}

type HistoryEntry struct {
	RequestID   string `json:"request_id"`
	ResponseID  string `json:"response_id,omitempty"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	StatusCode  int    `json:"status_code,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	BodySize    int    `json:"body_size_bytes,omitempty"`
	TimeMs      int64  `json:"time_ms,omitempty"`
	Source      string `json:"source"`
	EndpointID  string `json:"endpoint_id,omitempty"`
	CreatedAt   string `json:"created_at"`
}

type Endpoint struct {
	ID                  string      `json:"id"`
	ProjectID           string      `json:"project_id"`
	Host                string      `json:"host"`
	Method              string      `json:"method"`
	PathTemplate        string      `json:"path_template"`
	CanonicalPath       string      `json:"canonical_path"`
	FirstSeen           string      `json:"first_seen"`
	LastSeen            string      `json:"last_seen"`
	AuthRequired        bool        `json:"auth_required"`
	RequestCount        int         `json:"request_count"`
	ObservedStatusCodes []int       `json:"observed_status_codes"`
	ContentTypes        []string    `json:"content_types"`
	Parameters          []Parameter `json:"parameters,omitempty"`
}

type Parameter struct {
	ID            string   `json:"id"`
	EndpointID    string   `json:"endpoint_id"`
	Name          string   `json:"name"`
	Location      string   `json:"location"`
	InferredType  string   `json:"inferred_type"`
	ExampleValues []string `json:"example_values"`
	ObservedIn    []string `json:"observed_in"`
}

type Session struct {
	ID            string            `json:"id"`
	ProjectID     string            `json:"project_id"`
	Name          string            `json:"name"`
	Role          string            `json:"role,omitempty"`
	Cookies       []CookieEntry     `json:"cookies"`
	Headers       []Header          `json:"headers"`
	Tokens        map[string]string `json:"tokens"`
	AuthProfileID string            `json:"auth_profile_id,omitempty"`
	CreatedAt     string            `json:"created_at"`
	UpdatedAt     string            `json:"updated_at"`
}

type CookieEntry struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site,omitempty"`
	Expires  string `json:"expires,omitempty"`
}

type Job struct {
	ID            string                 `json:"id"`
	ProjectID     string                 `json:"project_id"`
	Type          string                 `json:"type"`
	Status        string                 `json:"status"`
	Config        map[string]interface{} `json:"config"`
	ResultSummary map[string]interface{} `json:"result_summary,omitempty"`
	CreatedAt     string                 `json:"created_at"`
	StartedAt     string                 `json:"started_at,omitempty"`
	FinishedAt    string                 `json:"finished_at,omitempty"`
	Error         string                 `json:"error,omitempty"`
}

type Signal struct {
	ID            string                 `json:"id"`
	ProjectID     string                 `json:"project_id"`
	Type          string                 `json:"type"`
	CheckID       string                 `json:"check_id"`
	Title         string                 `json:"title"`
	Severity      string                 `json:"severity"`
	Confidence    string                 `json:"confidence"`
	EndpointID    string                 `json:"endpoint_id,omitempty"`
	RequestID     string                 `json:"request_id,omitempty"`
	ResponseID    string                 `json:"response_id,omitempty"`
	Evidence      map[string]interface{} `json:"evidence"`
	Explanation   string                 `json:"explanation"`
	Remediation   string                 `json:"remediation,omitempty"`
	FalsePositive bool                   `json:"false_positive"`
	Retested      bool                   `json:"retested"`
	CreatedAt     string                 `json:"created_at"`
}

type Event struct {
	ID         string                 `json:"id"`
	ProjectID  string                 `json:"project_id,omitempty"`
	Timestamp  string                 `json:"timestamp"`
	Actor      string                 `json:"actor"`
	Action     string                 `json:"action"`
	ObjectType string                 `json:"object_type,omitempty"`
	ObjectID   string                 `json:"object_id,omitempty"`
	Result     string                 `json:"result"`
	Detail     map[string]interface{} `json:"detail,omitempty"`
}

type Note struct {
	ID         string `json:"id"`
	ProjectID  string `json:"project_id"`
	ObjectType string `json:"object_type,omitempty"`
	ObjectID   string `json:"object_id,omitempty"`
	Content    string `json:"content"`
	CreatedAt  string `json:"created_at"`
}

type ScopeRule struct {
	ID          string `json:"id"`
	ProjectID   string `json:"project_id"`
	Action      string `json:"action"`
	Pattern     string `json:"pattern"`
	PatternType string `json:"pattern_type"`
	CreatedAt   string `json:"created_at"`
}

type FuzzResult struct {
	ID            string            `json:"id"`
	JobID         string            `json:"job_id"`
	RequestID     string            `json:"request_id,omitempty"`
	ResponseID    string            `json:"response_id,omitempty"`
	Payloads      map[string]string `json:"payloads"`
	Anomaly       bool              `json:"anomaly"`
	AnomalyReason string            `json:"anomaly_reason,omitempty"`
	Status        int               `json:"status_code"`
	Length        int               `json:"length_bytes"`
	TimeMS        int64             `json:"time_ms"`
	CreatedAt     string            `json:"created_at"`
}

type CrawlEntry struct {
	URL           string `json:"url"`
	Method        string `json:"method"`
	Status        int    `json:"status_code"`
	Depth         int    `json:"depth"`
	DiscoveredVia string `json:"discovered_via,omitempty"`
	RequestID     string `json:"request_id,omitempty"`
	ResponseID    string `json:"response_id,omitempty"`
}

type ImportSummary struct {
	Source          string         `json:"source"`
	Format          string         `json:"format"`
	RequestsCreated int            `json:"requests_created"`
	Endpoints       int            `json:"endpoints"`
	Warnings        []string       `json:"warnings,omitempty"`
	Methods         map[string]int `json:"methods,omitempty"`
}
