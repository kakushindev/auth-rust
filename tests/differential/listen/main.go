// Records how Go's net.Listen("tcp", address) binds each listen address that
// 2026.2.7's Go front server could be configured with (config listen.*).
// Run by run.sh in golang:1.25.5 (the Go 2026.2.7 is built with); the JSON it
// prints is replayed against the Rust parser and binder by
// rust/packages/ak-axum/src/server.rs `go_listen_matches_go`.
package main

import (
	"encoding/json"
	"net"
	"os"
	"syscall"
)

type result struct {
	Address string `json:"address"`
	// Error is true when net.Listen fails; the message is not compared.
	Error  bool   `json:"error"`
	Family string `json:"family,omitempty"`
	IP     string `json:"ip,omitempty"`
	// Port is -1 when the kernel picked a random port.
	Port   int  `json:"port,omitempty"`
	V6Only bool `json:"v6only,omitempty"`
}

var addresses = []string{
	"0.0.0.0:19001",
	"[::]:19002",
	":19003",
	"127.0.0.1:19004",
	"[::1]:19005",
	"[::ffff:127.0.0.1]:19006",
	"[::ffff:0.0.0.0]:19007",
	"localhost:19008",
	"[0.0.0.0]:19009",
	"0.0.0.0:+19010",
	"0.0.0.0:019011",
	"0.0.0.0:",
	"0.0.0.0:+",
	"0.0.0.0:-",
	"0.0.0.0:-0",
	"0.0.0.0:-1",
	"0.0.0.0:65536",
	"0.0.0.0:99999999999999999999",
	"0.0.0.0:9x",
	"0.0.0.0:+-1",
	"0.0.0.0",
	"::1:19012",
	"[::1]19013",
	"[::1]",
	"[::1",
	"::1]:19014",
	"[[::1]]:19015",
	"[::1]:19016]",
	"0.0.0.0:19017,0.0.0.0:19018",
	"192.0.2.1:19019",
	"no-such-host.invalid:19020",
	"010.0.0.1:19021",
}

func main() {
	results := make([]result, 0, len(addresses))
	for _, address := range addresses {
		r := result{Address: address}
		ln, err := net.Listen("tcp", address)
		if err != nil {
			r.Error = true
			results = append(results, r)
			continue
		}
		addr := ln.Addr().(*net.TCPAddr)
		r.IP = addr.IP.String()
		r.Port = addr.Port
		if _, port, _ := net.SplitHostPort(address); port == "" || port == "+" || port == "-" || port == "-0" {
			r.Port = -1
		}
		raw, err := ln.(*net.TCPListener).SyscallConn()
		if err != nil {
			panic(err)
		}
		if err := raw.Control(func(fd uintptr) {
			sa, err := syscall.Getsockname(int(fd))
			if err != nil {
				panic(err)
			}
			switch sa.(type) {
			case *syscall.SockaddrInet4:
				r.Family = "inet"
			case *syscall.SockaddrInet6:
				r.Family = "inet6"
				v, err := syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY)
				if err != nil {
					panic(err)
				}
				r.V6Only = v != 0
			}
		}); err != nil {
			panic(err)
		}
		ln.Close()
		results = append(results, r)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		panic(err)
	}
}
