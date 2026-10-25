package mcpproxy

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

const (
	testSecret = "s3cr3t-shared-value"
	testCookie = "session=c00kie-value"
	testEmail  = "alice@example.test"
	testBearer = "Bearer t0ken-value"
)

func runRecovery(t *testing.T, panicValue any) (*httptest.ResponseRecorder, *observer.ObservedLogs) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	core, logs := observer.New(zapcore.DebugLevel)
	router := gin.New()
	router.Use(recoveryMiddleware(zap.New(core)))
	router.GET("/mcp", func(c *gin.Context) {
		// Mimic the proxy: the request is mutated with secrets before the panic.
		c.Request.Header.Set("X-Gw-Shared-Secret", testSecret)
		c.Request.Header.Set("X-Forwarded-Email", testEmail)
		panic(panicValue)
	})

	req := httptest.NewRequest(http.MethodGet, "/mcp?q=1", nil)
	req.Header.Set("Cookie", testCookie)
	req.Header.Set("Authorization", testBearer)
	w := httptest.NewRecorder()
	require.NotPanics(t, func() { router.ServeHTTP(w, req) })
	return w, logs
}

func requireNoSensitiveData(t *testing.T, logs *observer.ObservedLogs) {
	t.Helper()
	for _, entry := range logs.All() {
		dump := entry.Message + " " + fmt.Sprint(entry.ContextMap())
		for _, needle := range []string{testSecret, "c00kie-value", testEmail, "t0ken-value", "X-Gw-Shared-Secret", "Cookie", "Authorization"} {
			require.False(t, strings.Contains(dump, needle), "log entry leaks %q: %s", needle, dump)
		}
	}
}

func TestRecoveryMiddleware_AbortHandler(t *testing.T) {
	_, logs := runRecovery(t, http.ErrAbortHandler)

	require.Equal(t, 0, logs.FilterLevelExact(zapcore.ErrorLevel).Len())
	entries := logs.FilterLevelExact(zapcore.DebugLevel).All()
	require.Len(t, entries, 1)
	require.Equal(t, "GET", entries[0].ContextMap()["method"])
	require.Equal(t, "/mcp", entries[0].ContextMap()["path"])
	require.NotContains(t, entries[0].ContextMap(), "stack")
	requireNoSensitiveData(t, logs)
}

func TestRecoveryMiddleware_BrokenConnection(t *testing.T) {
	for name, errno := range map[string]syscall.Errno{"broken pipe": syscall.EPIPE, "reset": syscall.ECONNRESET} {
		t.Run(name, func(t *testing.T) {
			err := &net.OpError{Op: "write", Net: "tcp", Err: os.NewSyscallError("write", errno)}
			_, logs := runRecovery(t, err)
			require.Equal(t, 0, logs.FilterLevelExact(zapcore.ErrorLevel).Len())
			require.Equal(t, 1, logs.FilterLevelExact(zapcore.DebugLevel).Len())
			requireNoSensitiveData(t, logs)
		})
	}
}

func TestRecoveryMiddleware_GenericPanic(t *testing.T) {
	w, logs := runRecovery(t, "boom")

	require.Equal(t, http.StatusInternalServerError, w.Code)
	entries := logs.FilterLevelExact(zapcore.ErrorLevel).All()
	require.Len(t, entries, 1)
	ctx := entries[0].ContextMap()
	require.Equal(t, "boom", ctx["error"])
	require.Equal(t, "/mcp", ctx["path"])
	require.Contains(t, ctx["stack"], "runtime/debug.Stack")
	require.NotContains(t, ctx, "request")
	requireNoSensitiveData(t, logs)
}

func TestRecoveryMiddleware_PanicAfterWrite(t *testing.T) {
	gin.SetMode(gin.TestMode)
	core, logs := observer.New(zapcore.DebugLevel)
	router := gin.New()
	router.Use(recoveryMiddleware(zap.New(core)))
	router.GET("/x", func(c *gin.Context) {
		c.String(http.StatusAccepted, "partial")
		panic("late")
	})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	require.Equal(t, http.StatusAccepted, w.Code)
	require.Equal(t, 1, logs.FilterLevelExact(zapcore.ErrorLevel).Len())
}
