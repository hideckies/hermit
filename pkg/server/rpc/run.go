package rpc

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/hideckies/hermit/pkg/common/certs"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/protobuf/rpcpb"
	"github.com/hideckies/hermit/pkg/server/state"
)

func Run(serverState *state.ServerState) {
	lis, lisErr := net.Listen("tcp", fmt.Sprintf("%s:%d", serverState.Conf.Host, serverState.Conf.Port))
	if lisErr != nil {
		stdout.LogFailed(fmt.Sprintf("%v", lisErr))
		os.Exit(1)
	}
	stdout.LogSuccess(fmt.Sprintf("The C2 server listening on %v\n", lis.Addr()))

	serverCertPath, serverKeyPath, err := certs.GetCertificatePath(certs.CATYPE_RPC, false, false, "")
	if err != nil {
		stdout.LogFailed(fmt.Sprintf("%v", err))
		os.Exit(1)
	}
	creds, err := credentials.NewServerTLSFromFile(serverCertPath, serverKeyPath)
	if err != nil {
		stdout.LogFailed(fmt.Sprintf("%v", err))
		os.Exit(1)
	}

	opts := []grpc.ServerOption{grpc.Creds(creds)}

	s := grpc.NewServer(opts...)
	rpcpb.RegisterHermitRPCServer(s, &HermitRPCServer{serverState: serverState})

	serverState.Job.ChServerStarted <- true
	if err := s.Serve(lis); err != nil {
		stdout.LogFailed(fmt.Sprintf("%v", err))
		serverState.Job.ChQuit <- syscall.SIGINT
	}
}
