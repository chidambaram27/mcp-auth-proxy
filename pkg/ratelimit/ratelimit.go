// Package ratelimit provides a small per-client-IP token bucket limiter for
// the proxy's unauthenticated endpoints (client registration, authorization,
// token and login).
package ratelimit

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// maxEntries bounds memory: when exceeded, idle entries are dropped first and,
// failing that, the table is reset.
const maxEntries = 100_000

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// Limiter limits requests per client IP (gin's ClientIP, which honours
// TRUSTED_PROXIES).
type Limiter struct {
	mu      sync.Mutex
	clients map[string]*entry
	rate    rate.Limit
	burst   int
	idle    time.Duration
	now     func() time.Time
}

// New allows perMinute requests per minute with the given burst per client.
func New(perMinute float64, burst int) *Limiter {
	return &Limiter{
		clients: map[string]*entry{},
		rate:    rate.Limit(perMinute / 60),
		burst:   burst,
		idle:    10 * time.Minute,
		now:     time.Now,
	}
}

func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e, ok := l.clients[key]
	if !ok {
		if len(l.clients) >= maxEntries {
			l.evict(now)
		}
		e = &entry{limiter: rate.NewLimiter(l.rate, l.burst)}
		l.clients[key] = e
	}
	e.lastSeen = now
	r := e.limiter.ReserveN(now, 1)
	if !r.OK() {
		return false, time.Minute
	}
	if d := r.DelayFrom(now); d > 0 {
		r.CancelAt(now)
		return false, d
	}
	return true, 0
}

func (l *Limiter) evict(now time.Time) {
	for k, e := range l.clients {
		if now.Sub(e.lastSeen) > l.idle {
			delete(l.clients, k)
		}
	}
	if len(l.clients) >= maxEntries {
		l.clients = map[string]*entry{}
	}
}

// Middleware rejects requests over the limit with 429 and Retry-After.
func (l *Limiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ok, retry := l.Allow(c.ClientIP())
		if !ok {
			c.Header("Retry-After", strconv.Itoa(int(math.Ceil(retry.Seconds()))))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too_many_requests", "error_description": "Too many requests. Try again later."})
			return
		}
		c.Next()
	}
}
