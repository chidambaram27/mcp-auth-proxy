//go:build !windows

package mcpproxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/idp"
	"github.com/stretchr/testify/require"
)

func TestSIGTERMDrainsInFlightRequests(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	t.Setenv("JWT_PRIVATE_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	t.Setenv("AUTH_HMAC_SECRET", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

	started := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	l.Close()
	external := "http://" + addr + "/"

	done := make(chan error, 1)
	go func() {
		done <- Run(addr, "", false, "", "", false, "", "",
			t.TempDir(), "local", "", external,
			"", "", nil, nil, "", "", "", "", nil, nil,
			"", "", "", nil, "", "", nil, nil, nil, nil,
			false, "", "", nil, nil, "", false,
			[]string{backend.URL}, false, nil, "/userinfo",
			"", "", "", "", idp.DefaultTokenLifespans(), nil)
	}()
	require.Eventually(t, func() bool {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
		}
		return err == nil
	}, 5*time.Second, 50*time.Millisecond)

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": external, "aud": external, "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(key)
	require.NoError(t, err)

	result := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			result <- -1
			return
		}
		resp.Body.Close()
		result <- resp.StatusCode
	}()
	<-started
	require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGTERM))

	require.Equal(t, http.StatusOK, <-result, "in-flight request completes during shutdown")
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after SIGTERM")
	}
}
