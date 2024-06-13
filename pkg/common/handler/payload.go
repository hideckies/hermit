package handler

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/hideckies/hermit/pkg/client/rpc"
	cliState "github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/meta"
	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/common/wizard"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

func HandlePayloadGen(
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if serverState.Conf != nil {
		// Get listeners for generating a payload from listener settings
		liss, err := serverState.DB.ListenerGetAll()
		if err != nil {
			return err
		}
		stdout.PrintBannerPayload()

		payloadType := wizard.WizardPayloadType()

		if strings.HasPrefix(payloadType, "implant") {
			imp, err := wizard.WizardPayloadImplant(
				meta.GetSpecificHost(serverState.Conf.Host),
				liss,
				payloadType,
			)
			if err != nil {
				return err
			}

			fmt.Println()
			spin := stdout.NewSpinner("Generating an payload...")
			spin.Start()

			_, outFile, err := imp.Generate(serverState)
			if err != nil {
				spin.Stop()
				return err
			}

			spin.Stop()
			stdout.LogSuccess(fmt.Sprintf("Implant saved at %s", color.HiGreenString(outFile)))
		} else if strings.HasPrefix(payloadType, "loader") {
			ldr, err := wizard.WizardPayloadLoader(
				meta.GetSpecificHost(serverState.Conf.Host),
				liss,
				payloadType,
			)
			if err != nil {
				return err
			}

			fmt.Println()
			spin := stdout.NewSpinner("Generating a payload...")
			spin.Start()

			_, outFile, err := ldr.Generate(serverState)
			if err != nil {
				spin.Stop()
				return err
			}

			spin.Stop()
			stdout.LogSuccess(fmt.Sprintf("Loader saved at %s", color.HiGreenString(outFile)))
		} else if strings.HasPrefix(payloadType, "module") {
			mod, err := wizard.WizardPayloadModule(
				meta.GetSpecificHost(serverState.Conf.Host),
				liss,
				payloadType,
			)
			if err != nil {
				return err
			}

			fmt.Println()
			spin := stdout.NewSpinner("Generating a payload...")
			spin.Start()

			_, outFile, err := mod.Generate(serverState)
			if err != nil {
				spin.Stop()
				return err
			}

			spin.Stop()
			stdout.LogSuccess(fmt.Sprintf("Module saved at %s", color.HiGreenString(outFile)))
		} else {
			return fmt.Errorf("invalid payload type")
		}
	} else if clientState.Conf != nil {
		// Get listeners for generating a payload from listener settings
		liss, err := rpc.RequestListenerGetAll(clientState)
		if err != nil {
			return err
		}

		stdout.PrintBannerPayload()

		payloadType := wizard.WizardPayloadType()

		if strings.HasPrefix(payloadType, "implant") {
			imp, err := wizard.WizardPayloadImplant(
				meta.GetSpecificHost(clientState.Conf.Server.Host), liss, payloadType)
			if err != nil {
				return err
			}

			spin := stdout.NewSpinner("Generating a payload...")
			spin.Start()
			data, err := rpc.RequestPayloadImplantGenerate(clientState, imp)
			if err != nil {
				spin.Stop()
				return err
			}
			spin.Stop()

			// Save the executable
			appDir, err := metafs.GetAppDir()
			if err != nil {
				return err
			}
			payloadsDir := fmt.Sprintf("%s/client/payloads", appDir)
			outFile := fmt.Sprintf("%s/%s.%s", payloadsDir, imp.Name, imp.Format)

			err = os.WriteFile(outFile, data, 0755)
			if err != nil {
				return err
			}

			stdout.LogSuccess(fmt.Sprintf("Implant saved at %s", color.HiGreenString(outFile)))
		} else if strings.HasPrefix(payloadType, "loader") {
			ldr, err := wizard.WizardPayloadLoader(
				meta.GetSpecificHost(clientState.Conf.Server.Host),
				liss,
				payloadType,
			)
			if err != nil {
				return err
			}

			spin := stdout.NewSpinner("Generating a payload...")
			spin.Start()
			data, err := rpc.RequestPayloadLoaderGenerate(clientState, ldr)
			if err != nil {
				spin.Stop()
				return err
			}
			spin.Stop()

			// Save the executable
			appDir, err := metafs.GetAppDir()
			if err != nil {
				return err
			}
			payloadsDir := fmt.Sprintf("%s/client/payloads", appDir)
			outFile := fmt.Sprintf("%s/%s.%s", payloadsDir, ldr.Name, ldr.Format)

			err = os.WriteFile(outFile, data, 0755)
			if err != nil {
				return err
			}

			stdout.LogSuccess(fmt.Sprintf("Stager saved at %s", color.HiGreenString(outFile)))
		} else if strings.HasPrefix(payloadType, "module") {
			mod, err := wizard.WizardPayloadModule(
				meta.GetSpecificHost(clientState.Conf.Server.Host),
				liss,
				payloadType,
			)
			if err != nil {
				return err
			}

			spin := stdout.NewSpinner("Generating a payload...")
			spin.Start()
			data, err := rpc.RequestPayloadModuleGenerate(clientState, mod)
			if err != nil {
				spin.Stop()
				return err
			}
			spin.Stop()

			// Save the executable
			appDir, err := metafs.GetAppDir()
			if err != nil {
				return err
			}
			payloadsDir := fmt.Sprintf("%s/client/payloads", appDir)
			outFile := fmt.Sprintf("%s/%s.%s", payloadsDir, mod.Name, mod.Format)

			err = os.WriteFile(outFile, data, 0755)
			if err != nil {
				return err
			}

			stdout.LogSuccess(fmt.Sprintf("Module saved at %s", color.HiGreenString(outFile)))
		} else {
			stdout.LogFailed("Invalid paylaod type.")
		}
	}

	return nil
}
