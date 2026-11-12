package mcpproxy

import (
	"errors"
	"net/http"
	"runtime/debug"
	"syscall"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// recoveryMiddleware recovers from panics in downstream handlers.
//
// Unlike ginzap.CustomRecoveryWithZap it never dumps the request: by the time
// a panic reaches it the request has already been rewritten by the proxy and
// carries secrets (PROXY_HEADERS values, cookies, mapped identity headers).
// Aborted connections (http.ErrAbortHandler from httputil.ReverseProxy when a
// streamed response is cut off, broken pipe, connection reset) are expected
// and only logged at debug level.
func recoveryMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			fields := []zap.Field{
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
			}
			if isConnectionAbort(rec) {
				logger.Debug("Request aborted", append(fields, zap.Any("error", rec))...)
				c.Abort()
				return
			}
			logger.Error("Recovered from panic", append(fields,
				zap.Any("error", rec),
				zap.String("stack", string(debug.Stack())),
			)...)
			if c.Writer.Written() {
				c.Abort()
				return
			}
			c.AbortWithStatus(http.StatusInternalServerError)
		}()
		c.Next()
	}
}

func isConnectionAbort(rec any) bool {
	err, ok := rec.(error)
	if !ok {
		return false
	}
	return errors.Is(err, http.ErrAbortHandler) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET)
}
