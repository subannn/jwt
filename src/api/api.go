package api

import (
	"fmt"
	"net/http"
	"time"
)

type APIServer struct {
	addr   string
	server *http.Server
}

func NewAPIServer(addr string, muxHandler *http.ServeMux) *APIServer {
	srv := &http.Server{
		Addr:           addr,
		Handler:        muxHandler,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	return &APIServer{
		addr:   addr,
		server: srv,
	}
}

func (srv *APIServer) RunServer() {
	fmt.Printf("Starting server on %s...\n", srv.addr)
	if err := srv.server.ListenAndServe(); err == nil {
		fmt.Println("Error starting server:", err)
	}
}
