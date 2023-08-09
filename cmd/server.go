package main

import (
	"context"
	"log"
	"net"

	"github.com/samar2170/cognitio/api/cognitio/api"
	"github.com/samar2170/cognitio/internal"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var grpcPort string

func init() {
	viper.SetConfigFile(".env")
	viper.ReadInConfig()
	grpcPort = viper.GetString("GRPC_PORT")

}

type grpcServer struct {
	api.UnimplementedAuthServiceServer
}

func (s *grpcServer) Login(ctx context.Context, req *api.LoginRequest) (*api.LoginResponse, error) {
	username, encryptedPassword := req.GetUsername(), req.GetPassword()
	token, err := internal.LoginUser(username, encryptedPassword)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &api.LoginResponse{Token: token}, nil
}

func (s *grpcServer) Signup(ctx context.Context, req *api.SignupRequest) (*api.SignupResponse, error) {
	username, encryptedPassword, email := req.GetUsername(), req.GetPassword(), req.GetEmail()
	cid, err := internal.SignupUser(email, username, encryptedPassword)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &api.SignupResponse{Response: cid}, nil
}

func (s *grpcServer) Authenticate(ctx context.Context, req *api.AuthRequest) (*api.AuthResponse, error) {
	token := req.GetToken()
	user, err := internal.VerifyToken(token)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &api.AuthResponse{Username: user.Username, UserCid: user.CID}, nil
}

func main() {
	log.Println("Starting server...")

	lis, err := net.Listen("tcp", ":"+grpcPort)
	log.Println("listening on port :", grpcPort)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	api.RegisterAuthServiceServer(s, &grpcServer{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
