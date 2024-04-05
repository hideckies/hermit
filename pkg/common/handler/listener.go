package handler

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/hideckies/hermit/pkg/client/rpc"
	cliState "github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/certs"
	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
	"github.com/hideckies/hermit/pkg/common/stdin"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/common/wizard"
	"github.com/hideckies/hermit/pkg/server/job"
	"github.com/hideckies/hermit/pkg/server/listener"
	"github.com/hideckies/hermit/pkg/server/service"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

func ListenerStart(lis *listener.Listener, lisJob *job.ListenerJob, serverState *servState.ServerState) error {
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

func HandleListenerNew(
	listenerURL string,
	domains []string,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	// Parse URL
	u, err := url.Parse(listenerURL)
	if err != nil {
		return err
	}

	// Protocol
	proto := u.Scheme
	if proto != "https" {
		return fmt.Errorf("only 'https' protocol is available")
	}

	// Port
	portStr := u.Port()
	portInt, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	// Confirm
	if !wizard.ConfirmListenerNew(u.String(), domains) {
		return fmt.Errorf("canceled")
	}

	lis := listener.NewListener(0, "", "", proto, u.Hostname(), uint16(portInt), domains, false)

	if serverState.Conf != nil {
		// Create new listener job
		lisJob := serverState.Job.NewListenerJob(lis.Uuid)

		go ListenerStart(lis, lisJob, serverState)
		err = serverState.Job.WaitListenerStart(serverState.DB, lis, lisJob)
		if err != nil {
			return err
		}

		stdout.LogSuccess("Listener started.")
	} else if clientState.Conf != nil {
		res, err := rpc.RequestListenerStart(clientState, lis)
		if err != nil {
			return err
		}

		stdout.LogSuccess(res)
	}

	return nil
}

func HandleListenerStartById(
	id uint,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if serverState.Conf != nil {
		lis, err := serverState.DB.ListenerGetById(id)
		if err != nil {
			return fmt.Errorf("listener not found: %v", err)
		}
		if lis.Active {
			return fmt.Errorf("the listener is already running")
		}

		// Get listener job
		lisJob, err := serverState.Job.GetListenerJob(lis.Uuid)
		if err != nil {
			return err
		}

		go ListenerStart(lis, lisJob, serverState)
		err = serverState.Job.WaitListenerStart(serverState.DB, lis, lisJob)
		if err != nil {
			return err
		}

		stdout.LogSuccess("Listener started.")
	} else if clientState.Conf != nil {
		// Request to RPC
		res, err := rpc.RequestListenerStartById(clientState, id)
		if err != nil {
			return fmt.Errorf("listener not found: %v", err)
		}

		stdout.LogSuccess(res)
	}

	return nil
}

func HandleListenerStopById(
	id uint,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if serverState.Conf != nil {
		lis, err := serverState.DB.ListenerGetById(id)
		if err != nil {
			return fmt.Errorf("listener not found: %v", err)
		}
		if !lis.Active {
			return fmt.Errorf("listener already stopped")
		}

		// Get listener job and send a channel to quit request
		lisJob, err := serverState.Job.GetListenerJob(lis.Uuid)
		if err != nil {
			return err
		}
		// serverState.Job.ChReqListenerQuit <- lis.Uuid
		lisJob.ChReqQuit <- lis.Uuid

		err = serverState.Job.WaitListenerStop(serverState.DB, lis)
		if err != nil {
			return err
		}

		stdout.LogSuccess("Listener stopped.")
	} else if clientState.Conf != nil {
		// Request to RPC
		res, err := rpc.RequestListenerStopById(clientState, id)
		if err != nil {
			return fmt.Errorf("listener not found: %v", err)
		}

		stdout.LogSuccess(res)
	}

	return nil
}

func HandleListenerDeleteById(
	id uint,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if serverState.Conf != nil {
		lis, err := serverState.DB.ListenerGetById(id)
		if err != nil {
			return fmt.Errorf("listener not found: %v", err)
		}
		if lis.Active {
			return fmt.Errorf("the listener is running. stop it before deleting")
		}

		// Delete listener from database
		err = serverState.DB.ListenerDeleteById(id)
		if err != nil {
			return err
		}

		// Delete listener job
		err = serverState.Job.RemoveListenerJob(lis.Uuid)
		if err != nil {
			return err
		}

		// Delete folder
		listenerDir, err := metafs.GetListenerDir(lis.Name, false)
		if err != nil {
			return err
		}
		err = os.RemoveAll(listenerDir)
		if err != nil {
			return err
		}

		stdout.LogSuccess("The listener deleted.")
	} else if clientState.Conf != nil {
		// Request to RPC
		res, err := rpc.RequestListenerDeleteById(clientState, id)
		if err != nil {
			return fmt.Errorf("listener not found: %v", err)
		}

		stdout.LogSuccess(res)
	}

	return nil
}

func HandleListenerInfoById(
	id uint,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if serverState.Conf != nil {
		lis, err := serverState.DB.ListenerGetById(id)
		if err != nil {
			return fmt.Errorf("listener not found: %v", err)
		}
		listener.PrintListenerDetails(lis)
	} else if clientState.Conf != nil {
		// Request to RPC
		lis, err := rpc.RequestListenerGetById(clientState, id)
		if err != nil {
			return fmt.Errorf("listener not found: %v", err)
		}
		listener.PrintListenerDetails(lis)
	}
	return nil
}

func HandleListenerList(
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if serverState.Conf != nil {
		liss, err := serverState.DB.ListenerGetAll()
		if err != nil {
			return err
		}
		listener.PrintListeners(liss)
	} else if clientState.Conf != nil {
		listeners, err := rpc.RequestListenerGetAll(clientState)
		if err != nil {
			return err
		}
		listener.PrintListeners(listeners)
	}
	return nil
}

func HandleListenerPayloadsById(
	id uint,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if serverState.Conf != nil {
		lis, err := serverState.DB.ListenerGetById(id)
		if err != nil {
			return fmt.Errorf("listener not found: %v", err)
		}

		// List payloads on the listener
		payloads, err := metafs.GetListenerPayloadPaths(lis.Name, false, true)
		if err != nil {
			return err
		}
		if len(payloads) == 0 {
			return fmt.Errorf("payloads not found on the listener")
		}

		// As needed, delete a specific payload.
		payloads = append(payloads, "Cancel")
		label := fmt.Sprintf("Payloads hosted on %s", lis.Name)
		res, err := stdin.Select(label, payloads)
		if err != nil {
			return err
		}
		if res == "Cancel" {
			return fmt.Errorf("canceled")
		}

		isDelete, err := stdin.Confirm(fmt.Sprintf("Delete '%s'?", res))
		if err != nil {
			return err
		}
		if isDelete {
			payloadsDir, err := metafs.GetListenerPayloadsDir(lis.Name, false)
			if err != nil {
				return err
			}
			err = os.RemoveAll(fmt.Sprintf("%s/%s", payloadsDir, res))
			if err != nil {
				return err
			}
			stdout.LogSuccess("Payload deleted.")
		} else {
			stdout.LogWarn("Canceled")
		}
	} else if clientState.Conf != nil {
		// Request to RPC
		lis, err := rpc.RequestListenerGetById(clientState, id)
		if err != nil {
			return err
		}

		payloads, err := rpc.RequestListenerPayloadsById(clientState, id)
		if err != nil {
			return fmt.Errorf("listener payloads not found: %v", err)
		}

		payloadsSplit := strings.Split(payloads, "\n")

		// As needed, delete a specific payload.
		payloadsSplit = append(payloadsSplit, "Cancel")
		label := fmt.Sprintf("Payloads hosted on %s", lis.Name)
		res, err := stdin.Select(label, payloadsSplit)
		if err != nil {
			return err
		}
		if res == "Cancel" {
			return fmt.Errorf("canceled")
		}

		isDelete, err := stdin.Confirm(fmt.Sprintf("Delete '%s'?", res))
		if err != nil {
			return err
		}
		if isDelete {
			// Request to delete a payload.
			_, err := rpc.RequestListenerPayloadsDeleteById(clientState, id, res)
			if err != nil {
				return err
			}
			stdout.LogSuccess("Payload deleted.")
		} else {
			stdout.LogWarn("Canceled")
		}
	}

	return nil
}
