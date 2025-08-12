package net

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/bitsbuster/utils/log"
)

type IPV string

const (
	IPV4 IPV = "tcp4"
	IPV6 IPV = "tcp6"
)

var httpServer *http.Server

// A ListenAndServeInfo defines parameters for running the HTTP server.
// The zero value for Server is a valid configuration.
type ListenAndServeInfo struct {
	Ipversion IPV //the ip version, tcp4 or tcp6
	// Addr optionally specifies the TCP address for the server to listen on,
	// in the form "host:port". If empty, ":http" (port 80) is used.
	// The service names are defined in RFC 6335 and assigned by IANA.
	// See net.Dial for details of the address format.
	Address string
	Handler http.Handler // handler to invoke, http.DefaultServeMux if nil

	// WriteTimeout is the maximum duration before timing out
	// writes of the response, in seconds. It is reset whenever a new
	// request's header is read. Like ReadTimeout, it does not
	// let Handlers make decisions on a per-request basis.
	WriteTimeout time.Duration
	// ReadTimeout is the maximum duration for reading the entire
	// request, including the body, in seconds.
	//
	// Because ReadTimeout does not let Handlers make per-request
	// decisions on each request body's acceptable deadline or
	// upload rate, most users will prefer to use
	// ReadHeaderTimeout. It is valid to use them both.
	ReadTimeout time.Duration
	// IdleTimeout is the maximum amount of time to wait for the
	// next request when keep-alives are enabled. If IdleTimeout
	// is zero, the value of ReadTimeout is used. If both are
	// zero, there is no timeout.
	IdleTimeout time.Duration
}

func ListenAndServe(l ListenAndServeInfo) error {

	httpServer = &http.Server{
		Addr:         l.Address,
		WriteTimeout: time.Second * l.WriteTimeout,
		ReadTimeout:  time.Second * l.ReadTimeout,
		IdleTimeout:  time.Second * l.IdleTimeout,
		Handler:      l.Handler,
	}

	addr := httpServer.Addr
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen(string(l.Ipversion), addr)
	if err != nil {
		return err
	}

	return httpServer.Serve(ln)
}

func ShutDown(reason string) {
	if len(strings.TrimSpace(reason)) == 0 {
		log.Print("Http server going down by request")
	} else {
		log.Printf(nil, "Http server going down by request. Reason: %s", reason)
	}
	httpServer.Shutdown(context.Background())
}

func GetConnectionError(err error) *syscall.Errno {
	urlerr, ok := err.(*url.Error)
	if !ok {
		return nil
	}
	operr, ok2 := urlerr.Err.(*net.OpError)
	if !ok2 {
		return nil
	}

	sysError, ok := operr.Err.(*os.SyscallError)
	if !ok {
		return nil
	}

	errno, ok := sysError.Err.(syscall.Errno)
	if !ok {
		return nil
	}

	return &errno

}
