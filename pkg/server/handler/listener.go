package handler

import (
	"fmt"
	"strings"

	"github.com/hideckies/hermit/pkg/common/certs"
	"github.com/hideckies/hermit/pkg/common/meta"
	"github.com/hideckies/hermit/pkg/server/listener"
	"github.com/hideckies/hermit/pkg/server/service"
	"github.com/hideckies/hermit/pkg/server/state"
)

func ListenerStart(lis *listener.Listener, serverState *state.ServerState) error {
	// Make a directory for the listener.
	err := meta.MakeListenerDir(lis.Name, false)
	if err != nil {
		return err
	}

	if strings.ToLower(lis.Protocol) == "https" {
		// Generate certificate
		err := certs.HTTPSGenerateCertificates(lis)
		if err != nil {
			serverState.Job.ChListenerError <- fmt.Sprint(err)
			return err
		}
		return service.HttpsStart(
			lis,
			serverState,
		)
	} else if strings.ToLower(lis.Protocol) == "grpc" {
		errorTxt := "gRPC listener is not implemented yet"
		serverState.Job.ChListenerError <- errorTxt
		return fmt.Errorf(errorTxt)
	} else {
		errorTxt := "protocols other than HTTPS are not implemented"
		serverState.Job.ChListenerError <- errorTxt
		return fmt.Errorf(errorTxt)
	}
}
