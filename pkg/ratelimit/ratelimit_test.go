package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestLimiterPerClient(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(60, 2)
	l.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		ok, _ := l.Allow("a")
		require.True(t, ok)
	}
	ok, retry := l.Allow("a")
	require.False(t, ok)
	require.Greater(t, retry, time.Duration(0))

	ok, _ = l.Allow("b")
	require.True(t, ok, "other clients are not affected")

	now = now.Add(time.Second)
	ok, _ = l.Allow("a")
	require.True(t, ok, "tokens refill")
}

func TestMiddlewareReturns429(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/x", New(1, 1).Middleware(), func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	require.Equal(t, http.StatusOK, w.Code)

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	require.NotEmpty(t, w.Header().Get("Retry-After"))
}
