package main

import (
	"log"
	"net"

	"github.com/samar2170/src/api"
	"google.golang.org/grpc"
)

func main() {
	log.Println("Starting listening on port 8080")
	port := ":8080"

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("Listening on %s", port)
	srv := NewGRPCServer()

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

type gprcServer struct {
	AuthService *api.AuthService
}

func NewGRPCServer() *grpc.Server {
	var as *api.AuthService
	var err error
	if as, err = api.NewAuthService(); err != nil {
		log.Fatal(err)
	}
	gsrv := grpc.NewServer()
	srv := &gprcServer{
		AuthService: as,
	}
	api.RegisterAuthServiceServer(gsrv, srv)
	return gsrv
}
