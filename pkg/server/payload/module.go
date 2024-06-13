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

const (
	MODULE_TYPE_CALC       = 1
	MODULE_TYPE_MESSAGEBOX = 2
)

func getModuleTypeId(modType string) (uint, error) {
	switch modType {
	case "Calc":
		return MODULE_TYPE_CALC, nil
	case "MessageBox":
		return MODULE_TYPE_MESSAGEBOX, nil
	default:
		return 0, fmt.Errorf("Invalid module type")
	}
}

type Module struct {
	Id        uint
	Uuid      string
	Name      string
	Os        string
	Arch      string
	Format    string
	Lprotocol string
	Lhost     string
	Lport     uint16
	Type      string
}

func NewModule(
	id uint,
	_uuid string,
	name string,
	os string,
	arch string,
	format string,
	lprotocol string,
	lhost string,
	lport uint16,
	_type string,
) *Module {
	if _uuid == "" {
		_uuid = uuid.NewString()
	}
	if name == "" {
		name = utils.GenerateRandomAnimalName(false, "module")
	}

	return &Module{
		Id:        id,
		Uuid:      _uuid,
		Name:      name,
		Os:        os,
		Arch:      arch,
		Format:    format,
		Lprotocol: lprotocol,
		Lhost:     lhost,
		Lport:     lport,
		Type:      _type,
	}
}

func (m *Module) Generate(serverState *state.ServerState) (data []byte, outFile string, err error) {
	// Get a corresponding listener
	liss, err := serverState.DB.ListenerGetAll()
	if err != nil {
		return nil, "", err
	}
	var lis *listener.Listener = nil
	for _, _lis := range liss {
		if _lis.Protocol == m.Lprotocol && (_lis.Addr == m.Lhost || slices.Contains(_lis.Domains, m.Lhost)) && _lis.Port == m.Lport {
			lis = _lis
			break
		}
	}
	if lis == nil {
		return nil, "", fmt.Errorf("a corresponding listener not found")
	}

	// Get output path
	payloadsDir, err := metafs.GetListenerPayloadsDir(lis.Name, false)
	if err != nil {
		return nil, "", err
	}
	outFile = fmt.Sprintf("%s/%s.%s.%s", payloadsDir, m.Name, m.Arch, m.Format)

	// Get request paths
	reqPathDownload := utils.GetRandomElemString(serverState.Conf.Listener.FakeRoutes["/loader/download"])

	// Generate random AES key and IV
	newAES, err := crypt.NewAES()
	if err != nil {
		return nil, "", err
	}

	// Get module type id
	modTypeId, err := getModuleTypeId(m.Type)
	if err != nil {
		return nil, "", fmt.Errorf("")
	}

	if m.Os == "linux" {
		return nil, "", fmt.Errorf("linux target is not implemented yet")
	} else if m.Os == "windows" {
		// Change to the payload directory
		os.Chdir("./payload/win/module")
		_, err = meta.ExecCommand("rm", "-rf", "build")
		if err != nil {
			os.Chdir(serverState.CWD)
			return nil, "", err
		}

		// Compile assembly and generate an object file.
		asmRflObj := fmt.Sprintf("/tmp/rfl-%s.o", uuid.NewString())
		asmRflSrc := "src/asm/rfl."
		asmFmt := "win"

		if m.Arch == "amd64" {
			asmRflSrc += "x64.asm"
			asmFmt += "64"
		} else {
			asmRflSrc += "x86.asm"
			asmFmt += "32"
		}

		_, err = meta.ExecCommand("nasm", "-f", asmFmt, "-o", asmRflObj, asmRflSrc)
		if err != nil {
			os.Chdir(serverState.CWD)
			return nil, "", fmt.Errorf("nasm error: %v", err)
		}

		// Compile
		outText, err := meta.ExecCommand(
			"cmake",
			fmt.Sprintf("-DASM_OBJ_REFLECTIVE=%s", asmRflObj),
			fmt.Sprintf("-DOUTPUT_DIRECTORY=%s", payloadsDir),
			fmt.Sprintf("-DPAYLOAD_NAME=%s", m.Name),
			fmt.Sprintf("-DPAYLOAD_ARCH=%s", m.Arch),
			fmt.Sprintf("-DPAYLOAD_FORMAT=%s", m.Format),
			fmt.Sprintf("-DMODULE_TYPE=%d", modTypeId),
			fmt.Sprintf("-DLISTENER_HOST=\"%s\"", m.Lhost),
			fmt.Sprintf("-DLISTENER_PORT=%s", fmt.Sprint(m.Lport)),
			fmt.Sprintf("-DREQUEST_PATH_DOWNLOAD=\"%s\"", reqPathDownload),
			fmt.Sprintf("-DAES_KEY_BASE64=\"%s\"", newAES.Key.Base64),
			fmt.Sprintf("-DAES_IV_BASE64=\"%s\"", newAES.IV.Base64),
			"-S.",
			"-Bbuild",
		)
		if err != nil {
			os.Chdir(serverState.CWD)
			os.Remove(asmRflObj)
			return nil, "", fmt.Errorf("cmake error: %v", err)
		}
		if strings.Contains(strings.ToLower(outText), "error:") {
			os.Chdir(serverState.CWD)
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
			os.Remove(asmRflObj)
			return nil, "", fmt.Errorf("cmake error: %v", err)
		}
		if strings.Contains(strings.ToLower(outText), "error:") {
			os.Chdir(serverState.CWD)
			os.Remove(asmRflObj)
			return nil, "", fmt.Errorf("cmake error: %s", outText)
		}

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

	data, err = os.ReadFile(outFile)
	if err != nil {
		os.Chdir(serverState.CWD)
		return nil, "", err
	}

	// Go back to the current directory
	os.Chdir(serverState.CWD)

	return data, outFile, nil
}
