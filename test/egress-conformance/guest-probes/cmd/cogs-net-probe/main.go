package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const version = "cogs.guest-probe/v1alpha1"
const maxConfigBytes = 128 * 1024

type config struct {
	Version          string            `json:"version"`
	Operation        string            `json:"operation"`
	Address          string            `json:"address,omitempty"`
	URL              string            `json:"url,omitempty"`
	Method           string            `json:"method,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	HostHeader       string            `json:"host_header,omitempty"`
	BodyBase64       string            `json:"body_base64,omitempty"`
	PayloadBase64    string            `json:"payload_base64,omitempty"`
	DNSName          string            `json:"dns_name,omitempty"`
	DNSServer        string            `json:"dns_server,omitempty"`
	DNSQType         string            `json:"dns_qtype,omitempty"`
	HTTPProtocol     string            `json:"http_protocol,omitempty"`
	CAPEM            string            `json:"ca_pem,omitempty"`
	ServerName       string            `json:"server_name,omitempty"`
	TimeoutMS        int               `json:"timeout_ms"`
	MaxResponseBytes int64             `json:"max_response_bytes,omitempty"`
}

type result struct {
	Version        string `json:"version"`
	Operation      string `json:"operation"`
	Outcome        string `json:"outcome"`
	DetailCode     string `json:"detail_code"`
	DurationMS     int64  `json:"duration_ms"`
	Root           bool   `json:"root"`
	StatusCode     int    `json:"status_code,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	ResponseBytes  int64  `json:"response_bytes,omitempty"`
	Truncated      bool   `json:"truncated,omitempty"`
	AnswerCount    int    `json:"answer_count,omitempty"`
	ArtifactSHA256 string `json:"artifact_sha256,omitempty"`
}

func main() {
	started := time.Now()
	type decoded struct {
		cfg config
		err error
	}
	input := make(chan decoded, 1)
	go func() {
		cfg, err := decodeConfig(os.Stdin)
		input <- decoded{cfg: cfg, err: err}
	}()
	var cfg config
	select {
	case decodedInput := <-input:
		if decodedInput.err != nil {
			emit(result{Version: version, Operation: "invalid", Outcome: "failed", DetailCode: "invalid-config", DurationMS: time.Since(started).Milliseconds(), Root: os.Geteuid() == 0})
			os.Exit(2)
		}
		cfg = decodedInput.cfg
	case <-time.After(5 * time.Second):
		emit(result{Version: version, Operation: "invalid", Outcome: "failed", DetailCode: "input-timeout", DurationMS: time.Since(started).Milliseconds(), Root: os.Geteuid() == 0})
		os.Exit(2)
	}
	out := run(cfg)
	out.DurationMS = time.Since(started).Milliseconds()
	emit(out)
}

func emit(value result) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(value)
}

func decodeConfig(reader io.Reader) (config, error) {
	limited := io.LimitReader(reader, maxConfigBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil || len(data) > maxConfigBytes {
		return config{}, errors.New("invalid config")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var cfg config
	if err := decoder.Decode(&cfg); err != nil {
		return config{}, errors.New("invalid config")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return config{}, errors.New("invalid config")
	}
	if err := validateConfig(cfg); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func validateConfig(cfg config) error {
	if cfg.Version != version || cfg.TimeoutMS < 100 || cfg.TimeoutMS > 30_000 {
		return errors.New("invalid config")
	}
	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = 64 * 1024
	}
	if cfg.MaxResponseBytes < 1 || cfg.MaxResponseBytes > 1024*1024 || len(cfg.Address) > 512 || len(cfg.URL) > 2048 || len(cfg.DNSName) > 253 || len(cfg.DNSServer) > 512 || len(cfg.ServerName) > 253 || len(cfg.HostHeader) > 255 || strings.ContainsAny(cfg.HostHeader, "\r\n") || len(cfg.CAPEM) > 64*1024 {
		return errors.New("invalid config")
	}
	allowed := map[string]bool{"root-check": true, "tcp": true, "udp": true, "dns": true, "http": true, "raw-tcp": true, "raw-tls": true}
	if !allowed[cfg.Operation] {
		return errors.New("invalid config")
	}
	if cfg.DNSQType != "" && cfg.DNSQType != "A" && cfg.DNSQType != "AAAA" {
		return errors.New("invalid config")
	}
	if cfg.HTTPProtocol != "" && cfg.HTTPProtocol != "http1" && cfg.HTTPProtocol != "http2" {
		return errors.New("invalid config")
	}
	if cfg.Operation == "tcp" || cfg.Operation == "udp" || cfg.Operation == "raw-tcp" || cfg.Operation == "raw-tls" {
		if !literalEndpoint(cfg.Address) {
			return errors.New("invalid config")
		}
	}
	if cfg.Operation == "dns" && (!literalEndpoint(cfg.DNSServer) || cfg.DNSName == "") {
		return errors.New("invalid config")
	}
	if cfg.Operation == "http" {
		parsed, err := url.Parse(cfg.URL)
		if err != nil || parsed.Hostname() == "" || net.ParseIP(parsed.Hostname()) == nil {
			return errors.New("invalid config")
		}
	}

	if len(cfg.Headers) > 32 {
		return errors.New("invalid config")
	}
	for name, value := range cfg.Headers {
		if len(name) == 0 || len(name) > 128 || len(value) > 8192 || strings.ContainsAny(name+value, "\r\n") {
			return errors.New("invalid config")
		}
	}
	for _, encoded := range []string{cfg.BodyBase64, cfg.PayloadBase64} {
		if len(encoded) > 96*1024 {
			return errors.New("invalid config")
		}
		if encoded != "" {
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil || len(decoded) > 64*1024 {
				return errors.New("invalid config")
			}
		}
	}
	return nil
}

func literalEndpoint(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil {
		return false
	}
	parsedPort, err := strconv.Atoi(port)
	return err == nil && parsedPort > 0 && parsedPort <= 65535
}

func baseResult(cfg config) result {
	return result{
		Version:        version,
		Operation:      cfg.Operation,
		Root:           os.Geteuid() == 0,
		ArtifactSHA256: executableDigest(),
	}
}

func executableDigest() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	binary, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer binary.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, binary); err != nil {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func run(cfg config) result {
	out := baseResult(cfg)
	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = 64 * 1024
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.TimeoutMS)*time.Millisecond)
	defer cancel()

	switch cfg.Operation {
	case "root-check":
		out.Outcome = "observed"
		out.DetailCode = map[bool]string{true: "guest-root", false: "not-root"}[out.Root]
		return out
	case "tcp":
		return runTCP(ctx, cfg, out)
	case "udp":
		return runUDP(ctx, cfg, out)
	case "dns":
		return runDNS(ctx, cfg, out)
	case "http":
		return runHTTP(ctx, cfg, out)
	case "raw-tcp":
		return runRaw(ctx, cfg, out, false)
	case "raw-tls":
		return runRaw(ctx, cfg, out, true)
	default:
		out.Outcome, out.DetailCode = "failed", "invalid-operation"
		return out
	}
}

func classifyNetworkError(err error) (string, string) {
	if err == nil {
		return "observed", "completed"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return "no-response", "timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused", "connection-refused"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "no-response", "timeout"
	}
	return "failed", "network-error"
}

func dial(ctx context.Context, network, address string) (net.Conn, error) {
	if address == "" {
		return nil, errors.New("missing address")
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func runTCP(ctx context.Context, cfg config, out result) result {
	connection, err := dial(ctx, "tcp", cfg.Address)
	if err != nil {
		out.Outcome, out.DetailCode = classifyNetworkError(err)
		return out
	}
	_ = connection.Close()
	out.Outcome, out.DetailCode = "reached", "connected"
	return out
}

func runUDP(ctx context.Context, cfg config, out result) result {
	connection, err := dial(ctx, "udp", cfg.Address)
	if err != nil {
		out.Outcome, out.DetailCode = classifyNetworkError(err)
		return out
	}
	defer connection.Close()
	deadline, _ := ctx.Deadline()
	_ = connection.SetDeadline(deadline)
	payload := []byte("cogs-denial-probe")
	if cfg.PayloadBase64 != "" {
		payload, _ = base64.StdEncoding.DecodeString(cfg.PayloadBase64)
	}
	if _, err := connection.Write(payload); err != nil {
		out.Outcome, out.DetailCode = classifyNetworkError(err)
		return out
	}
	buffer := make([]byte, min(cfg.MaxResponseBytes, 64*1024))
	count, err := connection.Read(buffer)
	if err != nil {
		out.Outcome, out.DetailCode = classifyNetworkError(err)
		return out
	}
	out.Outcome, out.DetailCode, out.ResponseBytes = "reached", "udp-response", int64(count)
	return out
}

func runDNS(ctx context.Context, cfg config, out result) result {
	query, identifier, err := dnsQuery(cfg.DNSName, cfg.DNSQType)
	if err != nil {
		out.Outcome, out.DetailCode = "failed", "invalid-config"
		return out
	}
	connection, err := dial(ctx, "udp", cfg.DNSServer)
	if err != nil {
		out.Outcome, out.DetailCode = classifyNetworkError(err)
		return out
	}
	defer connection.Close()
	deadline, _ := ctx.Deadline()
	_ = connection.SetDeadline(deadline)
	if _, err := connection.Write(query); err != nil {
		out.Outcome, out.DetailCode = classifyNetworkError(err)
		return out
	}
	response := make([]byte, 4096)
	count, err := connection.Read(response)
	if err != nil {
		out.Outcome, out.DetailCode = classifyNetworkError(err)
		return out
	}
	if count < 12 || binary.BigEndian.Uint16(response[:2]) != identifier || response[2]&0x80 == 0 {
		out.Outcome, out.DetailCode = "failed", "invalid-dns-response"
		return out
	}
	rcode := response[3] & 0x0f
	codes := map[byte]string{0: "dns-noerror", 1: "dns-formerr", 2: "dns-servfail", 3: "dns-nxdomain", 5: "dns-refused"}
	code, exists := codes[rcode]
	if !exists {
		code = "dns-other-rcode"
	}
	out.Outcome, out.DetailCode = "reached", code
	out.AnswerCount = int(binary.BigEndian.Uint16(response[6:8]))
	out.ResponseBytes = int64(count)
	return out
}

func dnsQuery(name, requestedType string) ([]byte, uint16, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return nil, 0, errors.New("invalid DNS name")
	}
	identifierBytes := []byte{0, 0}
	if _, err := rand.Read(identifierBytes); err != nil {
		return nil, 0, err
	}
	identifier := binary.BigEndian.Uint16(identifierBytes)
	query := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(query[:2], identifier)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, 0, errors.New("invalid DNS name")
		}
		for _, character := range []byte(label) {
			if !(character == '-' || character >= '0' && character <= '9' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z') {
				return nil, 0, errors.New("invalid DNS name")
			}
		}
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0)
	queryType := uint16(1)
	if requestedType == "AAAA" {
		queryType = 28
	}
	query = binary.BigEndian.AppendUint16(query, queryType)
	query = binary.BigEndian.AppendUint16(query, 1)
	return query, identifier, nil
}

func tlsConfig(cfg config) (*tls.Config, error) {
	var roots *x509.CertPool
	if cfg.CAPEM == "" {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil || roots == nil {
			return nil, errors.New("system CA unavailable")
		}
	} else {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(cfg.CAPEM)) {
			return nil, errors.New("invalid CA")
		}
	}
	return &tls.Config{RootCAs: roots, ServerName: cfg.ServerName, MinVersion: tls.VersionTLS12}, nil
}

func runHTTP(ctx context.Context, cfg config, out result) result {
	parsed, err := url.Parse(cfg.URL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		out.Outcome, out.DetailCode = "failed", "invalid-url"
		return out
	}
	body := []byte(nil)
	if cfg.BodyBase64 != "" {
		body, _ = base64.StdEncoding.DecodeString(cfg.BodyBase64)
	}
	method := cfg.Method
	if method == "" {
		method = http.MethodGet
	}
	request, err := http.NewRequestWithContext(ctx, method, cfg.URL, bytes.NewReader(body))
	if err != nil {
		out.Outcome, out.DetailCode = "failed", "invalid-request"
		return out
	}
	for name, value := range cfg.Headers {
		request.Header.Set(name, value)
	}
	if cfg.HostHeader != "" {
		request.Host = cfg.HostHeader
	}
	tlsSettings, err := tlsConfig(cfg)
	if err != nil {
		out.Outcome, out.DetailCode = "failed", "invalid-ca"
		return out
	}
	transport := &http.Transport{
		Proxy:                  nil,
		TLSClientConfig:        tlsSettings,
		ForceAttemptHTTP2:      cfg.HTTPProtocol != "http1",
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 * 1024,
	}
	if cfg.HTTPProtocol == "http1" {
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		out.Outcome, out.DetailCode = classifyNetworkError(err)
		return out
	}
	defer response.Body.Close()
	count, truncated, err := readBounded(response.Body, cfg.MaxResponseBytes)
	if err != nil {
		out.Outcome, out.DetailCode = "failed", "response-read-error"
		return out
	}
	if cfg.HTTPProtocol == "http2" && response.ProtoMajor != 2 {
		out.Outcome, out.DetailCode = "failed", "protocol-fallback"
		return out
	}
	if cfg.HTTPProtocol == "http1" && response.ProtoMajor != 1 {
		out.Outcome, out.DetailCode = "failed", "protocol-fallback"
		return out
	}
	protocol := "HTTP/1.1"
	if response.ProtoMajor == 2 {
		protocol = "HTTP/2.0"
	}
	out.Outcome, out.DetailCode = "reached", "http-response"
	out.StatusCode, out.Protocol, out.ResponseBytes, out.Truncated = response.StatusCode, protocol, count, truncated
	return out
}

func runRaw(ctx context.Context, cfg config, out result, secure bool) result {
	connection, err := dial(ctx, "tcp", cfg.Address)
	if err != nil {
		out.Outcome, out.DetailCode = classifyNetworkError(err)
		return out
	}
	if secure {
		tlsSettings, tlsErr := tlsConfig(cfg)
		if tlsErr != nil {
			_ = connection.Close()
			out.Outcome, out.DetailCode = "failed", "invalid-ca"
			return out
		}
		tlsConnection := tls.Client(connection, tlsSettings)
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			_ = connection.Close()
			out.Outcome, out.DetailCode = classifyNetworkError(err)
			return out
		}
		connection = tlsConnection
	}
	defer connection.Close()
	deadline, _ := ctx.Deadline()
	_ = connection.SetDeadline(deadline)
	payload, _ := base64.StdEncoding.DecodeString(cfg.PayloadBase64)
	if _, err := connection.Write(payload); err != nil {
		out.Outcome, out.DetailCode = classifyNetworkError(err)
		return out
	}
	reader := bufio.NewReader(io.LimitReader(connection, cfg.MaxResponseBytes+1))
	count, truncated, err := readBounded(reader, cfg.MaxResponseBytes)
	if err != nil && !errors.Is(err, io.EOF) {
		out.Outcome, out.DetailCode = classifyNetworkError(err)
		return out
	}
	out.Outcome, out.DetailCode, out.ResponseBytes, out.Truncated = "reached", "raw-response", count, truncated
	return out
}

func readBounded(reader io.Reader, maximum int64) (int64, bool, error) {
	count, err := io.Copy(io.Discard, io.LimitReader(reader, maximum+1))
	if err != nil {
		return count, false, err
	}
	return min(count, maximum), count > maximum, nil
}
