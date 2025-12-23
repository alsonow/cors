// Package cors
// Copyright 2025 alsonow. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.
package cors

import (
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/alsonow/alsonow"
)

type Config struct {
	AllowOrigins     []string
	AllowAllOrigins  bool
	AllowMethods     []string
	AllowHeaders     []string
	AllowCredentials bool
	MaxAge           int
}

func CORS(cfg Config) alsonow.HandlerFunc {
	if cfg.AllowAllOrigins && cfg.AllowCredentials {
		panic("cors: AllowAllOrigins=true conflicts with AllowCredentials=true")
	}

	if len(cfg.AllowMethods) == 0 {
		cfg.AllowMethods = []string{"GET", "POST", "HEAD"}
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 86400
	}

	methods := strings.Join(cfg.AllowMethods, ", ")
	headers := strings.Join(cfg.AllowHeaders, ", ")
	maxAge := strconv.Itoa(cfg.MaxAge)

	return func(c *alsonow.Context) {
		origin := c.Req.Header.Get("Origin")
		if origin == "" {
			c.Next()
			return
		}

		allowed := cfg.AllowAllOrigins
		if !allowed {
			if slices.Contains(cfg.AllowOrigins, origin) {
				allowed = true
			}
		}

		if !allowed {
			c.Next()
			return
		}

		if cfg.AllowAllOrigins {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Add("Vary", "Origin")
		}

		if cfg.AllowCredentials {
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if methods != "" {
			c.Writer.Header().Set("Access-Control-Allow-Methods", methods)
		}
		if headers != "" {
			c.Writer.Header().Set("Access-Control-Allow-Headers", headers)
		}
		c.Writer.Header().Set("Access-Control-Max-Age", maxAge)

		if c.Req.Method == http.MethodOptions &&
			c.Req.Header.Get("Access-Control-Request-Method") != "" {
			c.Writer.WriteHeader(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func Default() alsonow.HandlerFunc {
	return CORS(Config{
		AllowAllOrigins: true,
		AllowMethods:    []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowHeaders:    []string{"Content-Type", "Authorization"},
		MaxAge:          86400,
	})
}
