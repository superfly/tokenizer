package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

type responseWriter interface {
	http.ResponseWriter
	http.Hijacker
}

type statusCodeRecorder struct {
	responseWriter
	statusCode int
}

func (w *statusCodeRecorder) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.responseWriter.WriteHeader(statusCode)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scw := &statusCodeRecorder{responseWriter: w.(responseWriter)}
		queryKeys := strings.Join(maps.Keys(r.URL.Query()), ", ")
		start := time.Now()

		next.ServeHTTP(scw, r)

		if scw.statusCode == 0 {
			scw.statusCode = http.StatusOK
		}

		logrus.WithFields(logrus.Fields{
			"method":    r.Method,
			"host":      r.Host,
			"path":      r.URL.Path,
			"queryKeys": string(queryKeys),
			"status":    scw.statusCode,
			"durms":     int64(time.Since(start) / time.Millisecond),
		}).Info()
	})
}
