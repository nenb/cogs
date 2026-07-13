package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func baseConfig(operation string) config {
	return config{Version: version, Operation: operation, TimeoutMS: 1000, MaxResponseBytes: 4096}
}

func TestTCPAndRawPositiveControls(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer connection.Close()
				buffer := make([]byte, 128)
				_, _ = connection.Read(buffer)
				_, _ = connection.Write([]byte("fixture-response"))
			}()
		}
	}()

	tcpConfig := baseConfig("tcp")
	tcpConfig.Address = listener.Addr().String()
	if got := run(tcpConfig); got.Outcome != "reached" || got.DetailCode != "connected" || len(got.ArtifactSHA256) != 64 {
		t.Fatalf("unexpected TCP result: %#v", got)
	}

	rawConfig := baseConfig("raw-tcp")
	rawConfig.Address = listener.Addr().String()
	rawConfig.PayloadBase64 = base64.StdEncoding.EncodeToString([]byte("probe-value-never-output"))
	if got := run(rawConfig); got.Outcome != "reached" || got.ResponseBytes == 0 {
		t.Fatalf("unexpected raw result: %#v", got)
	}
}

func TestUDPEchoAndSilentOutcomes(t *testing.T) {
	echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buffer := make([]byte, 128)
		count, address, readErr := echo.ReadFrom(buffer)
		if readErr == nil {
			_, _ = echo.WriteTo(buffer[:count], address)
		}
	}()
	cfg := baseConfig("udp")
	cfg.Address = echo.LocalAddr().String()
	if got := run(cfg); got.Outcome != "reached" || got.DetailCode != "udp-response" {
		t.Fatalf("unexpected UDP result: %#v", got)
	}

	silent, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	cfg.Address = silent.LocalAddr().String()
	cfg.TimeoutMS = 100
	if got := run(cfg); got.Outcome != "no-response" {
		t.Fatalf("unexpected silent UDP result: %#v", got)
	}
}

func TestHTTP1AndHTTP2TLSWithoutValueReflection(t *testing.T) {
	secret := "guest-probe-header-secret"
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != secret || request.Host != "forged.fixture.test" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(response, strings.Repeat("x", 32))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	certificate := server.Certificate()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
	cfg := baseConfig("http")
	cfg.URL = server.URL
	cfg.CAPEM = caPEM
	cfg.Headers = map[string]string{"Authorization": secret}
	cfg.HostHeader = "forged.fixture.test"
	cfg.HTTPProtocol = "http2"
	got := run(cfg)
	if got.Outcome != "reached" || got.StatusCode != http.StatusOK || got.Protocol != "HTTP/2.0" || got.ResponseBytes != 32 {
		t.Fatalf("unexpected HTTP/2 result: %#v", got)
	}
	if strings.Contains(got.DetailCode, secret) || strings.Contains(got.Protocol, secret) {
		t.Fatal("result reflected a header value")
	}
	cfg.HTTPProtocol = "http1"
	if http1 := run(cfg); http1.Outcome != "reached" || http1.Protocol != "HTTP/1.1" {
		t.Fatalf("unexpected HTTP/1.1 result: %#v", http1)
	}
}

func TestCustomDNSPositiveControl(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go answerOneARecord(server)

	cfg := baseConfig("dns")
	cfg.DNSServer = server.LocalAddr().String()
	cfg.DNSName = "fixture.test"
	got := run(cfg)
	if got.Outcome != "reached" || got.AnswerCount < 1 {
		t.Fatalf("unexpected DNS result: %#v", got)
	}
}

func answerOneARecord(server net.PacketConn) {
	for {
		buffer := make([]byte, 512)
		count, address, err := server.ReadFrom(buffer)
		if err != nil || count < 16 {
			return
		}
		query := buffer[:count]
		end := 12
		for end < len(query) && query[end] != 0 {
			end += int(query[end]) + 1
		}
		end += 5
		if end > len(query) {
			continue
		}
		queryType := binary.BigEndian.Uint16(query[end-4 : end-2])
		response := make([]byte, 12, 12+(end-12)+28)
		copy(response[:2], query[:2])
		binary.BigEndian.PutUint16(response[2:4], 0x8180)
		binary.BigEndian.PutUint16(response[4:6], 1)
		binary.BigEndian.PutUint16(response[6:8], 1)
		response = append(response, query[12:end]...)
		response = append(response, 0xc0, 0x0c, byte(queryType>>8), byte(queryType), 0x00, 0x01, 0, 0, 0, 0)
		if queryType == 28 {
			response = append(response, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
		} else {
			response = append(response, 0, 4, 127, 0, 0, 1)
		}
		_, _ = server.WriteTo(response, address)
	}
}

func TestConfigIsBoundedAndUnknownFieldsFail(t *testing.T) {
	valid := `{"version":"cogs.guest-probe/v1alpha1","operation":"root-check","timeout_ms":100}`
	if _, err := decodeConfig(strings.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
	unknown := `{"version":"cogs.guest-probe/v1alpha1","operation":"root-check","timeout_ms":100,"credential":"must-not-be-accepted"}`
	if _, err := decodeConfig(strings.NewReader(unknown)); err == nil {
		t.Fatal("unknown credential field was accepted")
	}
	if _, err := decodeConfig(strings.NewReader(strings.Repeat("x", maxConfigBytes+1))); err == nil {
		t.Fatal("oversized config was accepted")
	}
}

func TestNetworkErrorsAreCategorical(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	cfg := baseConfig("tcp")
	cfg.Address = address
	got := run(cfg)
	if got.Outcome != "refused" || got.DetailCode != "connection-refused" || strings.Contains(got.DetailCode, address) {
		t.Fatalf("network error was not categorical: %#v", got)
	}
}

func TestRootObservationIsInternallyConsistent(t *testing.T) {
	cfg := baseConfig("root-check")
	if got := run(cfg); got.DetailCode != map[bool]string{true: "guest-root", false: "not-root"}[got.Root] {
		t.Fatalf("root result inconsistent: %#v", got)
	}
}

func TestDialHonorsContextDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	_, err := dial(ctx, "tcp", "192.0.2.1:443")
	if err == nil {
		t.Fatal("expired context unexpectedly connected")
	}
}
