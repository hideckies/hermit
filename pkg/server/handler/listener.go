package handler

import (
	"fmt"
	"strings"

	"github.com/hideckies/hermit/pkg/common/certs"
	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
	"github.com/hideckies/hermit/pkg/server/job"
	"github.com/hideckies/hermit/pkg/server/listener"
	"github.com/hideckies/hermit/pkg/server/service"
	"github.com/hideckies/hermit/pkg/server/state"
)

func ListenerStart(lis *listener.Listener, lisJob *job.ListenerJob, serverState *state.ServerState) error {
	// Make a directory for the listener.
	err := metafs.MakeListenerChildDirs(lis.Name, false)
	if err != nil {
		return err
	}

	if strings.ToLower(lis.Protocol) == "https" {
		// Generate certificate
		err := certs.HTTPSGenerateCertificates(lis)
		if err != nil {
			lisJob.ChError <- fmt.Sprint(err)
			return err
		}
		return service.HttpsStart(
			lis,
			lisJob,
			serverState,
		)
	} else if strings.ToLower(lis.Protocol) == "grpc" {
		errorTxt := "gRPC listener is not implemented yet"
		lisJob.ChError <- errorTxt
		return fmt.Errorf(errorTxt)
	} else {
		errorTxt := "protocols other than HTTPS are not implemented"
		lisJob.ChError <- errorTxt
		return fmt.Errorf(errorTxt)
	}
}
