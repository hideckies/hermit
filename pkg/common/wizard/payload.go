package wizard

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/hideckies/hermit/pkg/common/meta"
	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
	"github.com/hideckies/hermit/pkg/common/stdin"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/server/listener"
	"github.com/hideckies/hermit/pkg/server/payload"
)

func WizardPayloadType() string {
	var payloadType string

	for {
		res, err := stdin.Select("What to generate?", []string{
			"implant",
			"loader",
			"module",
		})
		if err != nil {
			stdout.LogFailed(fmt.Sprint(err))
			continue
		}
		payloadType = res
		break
	}

	if payloadType == "implant" {
		for {
			res, err := stdin.Select("Implant type", []string{
				"beacon",
				// "session",
			})
			if err != nil {
				stdout.LogFailed(fmt.Sprint(err))
				continue
			}
			payloadType += "/" + res
			break
		}
	} else if payloadType == "loader" {
		for {
			res, err := stdin.Select("Loader type", []string{
				"dll-loader",
				"pe-loader",
				"shellcode-loader",
			})
			if err != nil {
				stdout.LogFailed(fmt.Sprint(err))
				continue
			}
			payloadType += "/" + res
			break
		}
	} else if payloadType == "module" {
		for {
			res, err := stdin.Select("Module type", []string{
				// "CredentialStealing",
				"Calc",
				"MessageBox",
			})
			if err != nil {
				stdout.LogFailed(fmt.Sprint(err))
				continue
			}
			payloadType += "/" + res
			break
		}
	}

	return payloadType
}

func wizardPayloadBase(
	host string,
	listeners []*listener.Listener,
	payloadType string,
) (
	oOs string,
	oArch string,
	oFormat string,
	oLprotocol string,
	oLhost string,
	oLport uint16,
	err error,
) {
	var items []string

	if strings.HasPrefix(payloadType, "implant") {
		items = []string{
			// "linux/amd64/elf",
			// "linux/i686/elf",
			"windows/amd64/bin",
			"windows/amd64/dll",
			"windows/amd64/exe",
			// "windows/i686/dll",
			// "windows/i686/exe",
		}
	} else if strings.HasPrefix(payloadType, "loader") {
		items = []string{
			"windows/amd64/bin",
			"windows/amd64/dll",
			"windows/amd64/exe",
		}
	} else if strings.HasPrefix(payloadType, "module") {
		items = []string{
			"windows/amd64/bin",
			"windows/amd64/dll",
			"windows/amd64/exe",
		}
	}

	for {
		res, err := stdin.Select("OS/Arch/Format", items)
		if err != nil {
			stdout.LogFailed("Invalid input.")
			continue
		}
		selected := strings.Split(res, "/")
		oOs = selected[0]
		oArch = selected[1]
		oFormat = selected[2]
		break
	}

	customUrl := true
	oLhost = host

	// Check if listeners exist.
	if len(listeners) > 0 {
		for {
			items := []string{}
			for _, lis := range listeners {
				allURLs := lis.GetAllURLs()
				for _, u := range allURLs {
					item := fmt.Sprintf("%s\t: %s", lis.Name, u)
					items = append(items, item)
				}
			}
			items = append(items, "Custom URL")

			res, err := stdin.Select("Listener URL to Connect", items)
			if err != nil {
				stdout.LogFailed(fmt.Sprint(err))
				continue
			}

			if res == "Custom URL" {
				customUrl = true
			} else {
				customUrl = false

				// Parse listener URL
				lisSplit := strings.Split(res, " ")
				lisURL := lisSplit[len(lisSplit)-1]
				parsedUrl, err := url.ParseRequestURI(lisURL)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				oLprotocol = parsedUrl.Scheme
				oLhost = parsedUrl.Hostname()
				oLport64, err := strconv.ParseUint(parsedUrl.Port(), 10, 64)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				oLport = uint16(oLport64)
			}
			break
		}
	}

	if customUrl {
		for {
			items := []string{"HTTPS"}
			res, err := stdin.Select("Listener Protocol", items)
			if err != nil {
				stdout.LogFailed("Invalid input.")
				continue
			}
			if res == "" {
				continue
			}
			oLprotocol = res
			break
		}

		for {
			res, err := stdin.ReadInput("Listener Host", host)
			if err != nil {
				stdout.LogFailed("Invalid input.")
				continue
			}
			if res == "" {
				continue
			}
			oLhost = res
			break
		}

		for {
			res, err := stdin.ReadInput("Listener Port", "")
			if err != nil {
				stdout.LogFailed("Invlaid input.")
				continue
			}
			if res == "" {
				continue
			}

			resU64, err := strconv.ParseUint(res, 10, 64)
			if err != nil {
				stdout.LogFailed("Invalid port number.")
				continue
			}
			oLport = uint16(resU64)
			break
		}
	}

	return oOs, oArch, oFormat, oLprotocol, oLhost, oLport, nil
}

func WizardPayloadImplant(
	host string,
	listeners []*listener.Listener,
	payloadType string,
) (*payload.Implant, error) {
	oOs, oArch, oFormat, oLprotocol, oLhost, oLport, err := wizardPayloadBase(host, listeners, payloadType)
	if err != nil {
		return nil, err
	}

	oType := strings.Replace(payloadType, "implant/", "", -1)

	var oSleep uint = 3
	if oType == "beacon" {
		for {
			res, err := stdin.ReadInput("Sleep", fmt.Sprint(oSleep))
			if err != nil {
				stdout.LogFailed(fmt.Sprint(err))
				continue
			}

			oSleep64, err := strconv.ParseUint(res, 10, 64)
			if err != nil {
				stdout.LogFailed(fmt.Sprint(err))
				continue
			}
			oSleep = uint(oSleep64)
			break
		}
	}

	var oJitter uint = 5
	if oType == "beacon" {
		for {
			res, err := stdin.ReadInput("Jitter", fmt.Sprint(oJitter))
			if err != nil {
				stdout.LogFailed(fmt.Sprint(err))
				continue
			}

			oJitter64, err := strconv.ParseUint(res, 10, 64)
			if err != nil {
				stdout.LogFailed(fmt.Sprint(err))
				continue
			}
			oJitter = uint(oJitter64)
			break
		}
	}

	var oKillDateStr string = meta.GetFutureDateTime(1, 0, 0)
	var oKillDate uint
	for {
		res, err := stdin.ReadInput("KillDate (UTC)", oKillDateStr)
		if err != nil {
			stdout.LogFailed(fmt.Sprint(err))
			continue
		}
		oKillDateInt, err := meta.ParseDateTimeInt(res)
		if err != nil {
			stdout.LogFailed(fmt.Sprint(err))
			continue
		}
		oKillDateStr = res
		oKillDate = uint(oKillDateInt)
		break
	}

	var oIndirectSyscalls bool = false
	for {
		yes, err := stdin.Confirm("Enable Indirect Syscalls?")
		if err != nil {
			stdout.LogFailed(fmt.Sprint(err))
			continue
		}
		oIndirectSyscalls = yes
		break
	}

	var oAntiDebug bool = false
	for {
		yes, err := stdin.Confirm("Enable Anti-Debug?")
		if err != nil {
			stdout.LogFailed(fmt.Sprint(err))
			continue
		}
		oAntiDebug = yes
		break
	}

	// Set compresssion (UPX) level
	var oCompLevel uint64 = 0
	if oFormat == "dll" || oFormat == "exe" {
		for {
			res, err := stdin.ReadInput("UPX Compression Level (select between 0 and 9)", strconv.FormatUint(oCompLevel, 10))
			if err != nil {
				stdout.LogFailed(fmt.Sprint(err))
				continue
			}
			oCompLevel, err = strconv.ParseUint(res, 10, 64)
			if err != nil {
				stdout.LogFailed(fmt.Sprint(err))
				continue
			}
			if 9 < oCompLevel {
				stdout.LogFailed("Select the level between 0 and 9.")
				continue
			}
			break
		}
	}

	table := []stdout.SingleTableItem{
		stdout.NewSingleTableItem("Type", oType),
		stdout.NewSingleTableItem("Target OS", oOs),
		stdout.NewSingleTableItem("Target Arch", oArch),
		stdout.NewSingleTableItem("Format", oFormat),
		stdout.NewSingleTableItem("Listener", fmt.Sprintf("%s://%s:%d", strings.ToLower(oLprotocol), oLhost, oLport)),
		stdout.NewSingleTableItem("Sleep", fmt.Sprint(oSleep)),
		stdout.NewSingleTableItem("Jitter", fmt.Sprint(oJitter)),
		stdout.NewSingleTableItem("KillDate (UTC)", oKillDateStr),
		stdout.NewSingleTableItem("Indirect Syscalls", fmt.Sprintf("%t", oIndirectSyscalls)),
		stdout.NewSingleTableItem("Anti-Debug", fmt.Sprintf("%t", oAntiDebug)),
		stdout.NewSingleTableItem("UPX Compression Level", fmt.Sprintf("%d", oCompLevel)),
	}
	stdout.PrintSingleTable("Implant Options", table)

	var proceed bool
	for {
		res, err := stdin.Confirm("Proceed?")
		if err != nil {
			continue
		}
		proceed = res
		break
	}
	if !proceed {
		return nil, fmt.Errorf("canceled")
	}

	return payload.NewImplant(
		0, "", "",
		oOs,
		oArch,
		oFormat,
		oLprotocol,
		oLhost,
		oLport,
		oType,
		oSleep,
		oJitter,
		oKillDate,
		oIndirectSyscalls,
		oAntiDebug,
		oCompLevel,
	), nil
}

func WizardPayloadLoader(
	host string,
	listeners []*listener.Listener,
	payloadType string,
) (*payload.Loader, error) {
	oOs, oArch, oFormat, oLprotocol, oLhost, oLport, err := wizardPayloadBase(host, listeners, payloadType)
	if err != nil {
		return nil, err
	}

	oType := strings.Replace(payloadType, "loader/", "", -1)

	var targetPayloadExt string
	if oType == "dll-loader" {
		targetPayloadExt = ".dll"
	} else if oType == "pe-loader" {
		targetPayloadExt = ".exe"
	} else if oType == "shellcode-loader" {
		targetPayloadExt = ".bin"
	}

	// Get a target listener and specify a payload to be loaded
	var targetLis listener.Listener
	for i := 0; i < len(listeners); i++ {
		lis := listeners[i]
		if lis.Port == oLport {
			targetLis = *lis
		}
	}
	payloads, err := metafs.GetListenerPayloadPaths(targetLis.Name, false, true)
	if err != nil {
		return nil, err
	}
	// Extract corresponding payloads
	var corrPayloads []string
	for i := 0; i < len(payloads); i++ {
		if strings.Contains(payloads[i], targetPayloadExt) {
			corrPayloads = append(corrPayloads, payloads[i])
		}
	}
	corrPayloads = append(corrPayloads, "Not specified (auto detection)")

	oPayloadToLoad, err := stdin.Select("Payload to be loaded by this loader", corrPayloads)
	if err != nil {
		return nil, err
	}
	if oPayloadToLoad == "Not specified (auto detection)" {
		oPayloadToLoad = ""
	}

	// Technique
	var oTechnique string
	var items []string
	if oType == "dll-loader" {
		// DLL Loader
		items = []string{
			"dll-injection",
			"reflective-dll-injection",
		}
	} else if oType == "pe-loader" {
		// PE Loader
		items = []string{
			"direct-execution",
			// "pe-injection",
			"process-hollowing",
			// "process-doppelganging",
			// "apc-que-code-injection",
			// "early-bird-apc-que-code-injection",
			// "process-ghosting",
			// "atom-bombing",
		}
	} else if oType == "shellcode-loader" {
		// Shellcode Loader
		items = []string{
			"shellcode-injection",
			"via-fibers",
			"via-apc-and-nttestalert",
			"early-bird-apc-queue-code-injection",
			"via-create-threadpool-wait",
			"thread-execution-hijacking",
			"via-memory-sections",
			"via-find-window",
			"via-kernel-callback-table",
			"rwx-hunting",
			"address-of-entry-point-injection",
			"module-stomping",
			"dirty-vanity",
			"process-mockingjay",
		}
	}
	for {
		res, err := stdin.Select("Injection Technique", items)
		if err != nil {
			continue
		}
		oTechnique = res
		break
	}

	// Target process name to inject
	var oProcessToInject string = ""
	if oTechnique == "dll-injection" ||
		oTechnique == "process-hollowing" ||
		oTechnique == "reflective-dll-injection" ||
		oTechnique == "shellcode-injection" ||
		oTechnique == "early-bird-apc-queue-code-injection" ||
		oTechnique == "thread-execution-hijacking" ||
		oTechnique == "via-memory-sections" ||
		oTechnique == "address-of-entry-point-injection" ||
		oTechnique == "module-stomping" ||
		oTechnique == "dirty-vanity" {
		for {
			res, err := stdin.ReadInput("Target Process to be Injected", "notepad.exe")
			if err != nil {
				continue
			}
			oProcessToInject = res
			break
		}
	}

	var oIndirectSyscalls bool = false
	for {
		yes, err := stdin.Confirm("Enable Indirect Syscalls?")
		if err != nil {
			stdout.LogFailed(fmt.Sprint(err))
			continue
		}
		oIndirectSyscalls = yes
		break
	}

	var oAntiDebug bool = false
	for {
		yes, err := stdin.Confirm("Enable Anti-Debug?")
		if err != nil {
			stdout.LogFailed(fmt.Sprint(err))
			continue
		}
		oAntiDebug = yes
		break
	}

	// Set compresssion (UPX) level
	var oCompLevel uint64 = 0
	if oFormat == "dll" || oFormat == "exe" {
		for {
			res, err := stdin.ReadInput("UPX Compression Level (select between 0 and 9)", strconv.FormatUint(oCompLevel, 10))
			if err != nil {
				stdout.LogFailed(fmt.Sprint(err))
				continue
			}
			oCompLevel, err = strconv.ParseUint(res, 10, 64)
			if err != nil {
				stdout.LogFailed(fmt.Sprint(err))
				continue
			}
			if 9 < oCompLevel {
				stdout.LogFailed("Select the level between 0 and 9.")
				continue
			}
			break
		}
	}

	table := []stdout.SingleTableItem{
		stdout.NewSingleTableItem("Target OS", oOs),
		stdout.NewSingleTableItem("Target Arch", oArch),
		stdout.NewSingleTableItem("Format", oFormat),
		stdout.NewSingleTableItem("Listener", fmt.Sprintf("%s://%s:%d", strings.ToLower(oLprotocol), oLhost, oLport)),
		stdout.NewSingleTableItem("Type", oType),
		stdout.NewSingleTableItem("Payload to be Loaded", oPayloadToLoad),
		stdout.NewSingleTableItem("Injection Technique", oTechnique),
		stdout.NewSingleTableItem("Target Process", oProcessToInject),
		stdout.NewSingleTableItem("Indirect Syscalls", fmt.Sprintf("%t", oIndirectSyscalls)),
		stdout.NewSingleTableItem("Anti-Debug", fmt.Sprintf("%t", oAntiDebug)),
		stdout.NewSingleTableItem("UPX Compression Level", fmt.Sprintf("%d", oCompLevel)),
	}
	stdout.PrintSingleTable("Loader Options", table)

	var proceed bool
	for {
		res, err := stdin.Confirm("Proceed?")
		if err != nil {
			continue
		}
		proceed = res
		break
	}
	if !proceed {
		return nil, fmt.Errorf("canceled")
	}

	return payload.NewLoader(
		0,
		"",
		"",
		oOs,
		oArch,
		oFormat,
		oLprotocol,
		oLhost,
		oLport,
		oType,
		oPayloadToLoad,
		oTechnique,
		oProcessToInject,
		oIndirectSyscalls,
		oAntiDebug,
		oCompLevel,
	), nil
}

func WizardPayloadModule(
	host string,
	listeners []*listener.Listener,
	payloadType string,
) (*payload.Module, error) {
	oOs, oArch, oFormat, oLprotocol, oLhost, oLport, err := wizardPayloadBase(host, listeners, payloadType)
	if err != nil {
		return nil, err
	}

	oType := strings.Replace(payloadType, "module/", "", -1)

	table := []stdout.SingleTableItem{
		stdout.NewSingleTableItem("Target OS", oOs),
		stdout.NewSingleTableItem("Target Arch", oArch),
		stdout.NewSingleTableItem("Format", oFormat),
		stdout.NewSingleTableItem("Listener", fmt.Sprintf("%s://%s:%d", strings.ToLower(oLprotocol), oLhost, oLport)),
		stdout.NewSingleTableItem("Type", oType),
	}
	stdout.PrintSingleTable("Module Options", table)

	var proceed bool
	for {
		res, err := stdin.Confirm("Proceed?")
		if err != nil {
			continue
		}
		proceed = res
		break
	}
	if !proceed {
		return nil, fmt.Errorf("canceled")
	}

	return payload.NewModule(
		0,
		"",
		"",
		oOs,
		oArch,
		oFormat,
		oLprotocol,
		oLhost,
		oLport,
		oType,
	), nil
}
