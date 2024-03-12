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

type ImplantRequestPaths struct {
	CheckIn    string
	TaskGet    string
	TaskResult string
	WebSocket  string
}

type Implant struct {
	Id           uint
	Uuid         string
	Name         string
	Os           string
	Arch         string
	Format       string
	Lprotocol    string
	Lhost        string
	Lport        uint16
	RequestPaths ImplantRequestPaths
	Type         string // "beacon", "interactive"
	Sleep        uint
	Jitter       uint
	KillDate     uint
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
) *Implant {
	if _uuid == "" {
		_uuid = uuid.NewString()
	}
	if name == "" {
		name = utils.GenerateRandomAnimalName(false, fmt.Sprintf("implant-%s", impType))
	}

	return &Implant{
		Id:        id,
		Uuid:      _uuid,
		Name:      name,
		Os:        os,
		Arch:      arch,
		Format:    format,
		Lprotocol: lprotocol,
		Lhost:     lhost,
		Lport:     lport,
		Type:      impType,
		Sleep:     sleep,
		Jitter:    jitter,
		KillDate:  killDate,
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
	payloadsDir, err := meta.GetPayloadsDir(lis.Name, false)
	if err != nil {
		return nil, "", err
	}
	outFile = fmt.Sprintf("%s/%s.%s.%s", payloadsDir, i.Name, i.Arch, i.Format)

	// Get request paths randomly
	requestPathCheckIn := utils.GetRandomElemString(serverState.Conf.Listener.FakeRoutes["/implant/checkin"])
	requestPathDownload := utils.GetRandomElemString(serverState.Conf.Listener.FakeRoutes["/download"])
	requestPathTaskGet := utils.GetRandomElemString(serverState.Conf.Listener.FakeRoutes["/implant/task/get"])
	requestPathTaskResult := utils.GetRandomElemString(serverState.Conf.Listener.FakeRoutes["/implant/task/result"])
	requestPathUpload := utils.GetRandomElemString(serverState.Conf.Listener.FakeRoutes["/upload"])
	requestPathWebSocket := utils.GetRandomElemString(serverState.Conf.Listener.FakeRoutes["/implant/websocket"])

	// Change to the paylaod directory
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

		_, err = meta.ExecCommand(
			"cmake",
			fmt.Sprintf("-DOUTPUT_DIRECTORY=%s", payloadsDir),
			fmt.Sprintf("-DPAYLOAD_NAME=%s", i.Name),
			fmt.Sprintf("-DPAYLOAD_ARCH=%s", i.Arch),
			fmt.Sprintf("-DPAYLOAD_FORMAT=%s", i.Format),
			fmt.Sprintf("-DPAYLOAD_TYPE=\"%s\"", i.Type),
			fmt.Sprintf("-DPAYLOAD_SLEEP=%s", fmt.Sprint(i.Sleep)),
			fmt.Sprintf("-DPAYLOAD_JITTER=%s", fmt.Sprint(i.Jitter)),
			fmt.Sprintf("-DPAYLOAD_KILLDATE=%s", fmt.Sprint(i.KillDate)),
			fmt.Sprintf("-DLISTENER_HOST=\"%s\"", i.Lhost),
			fmt.Sprintf("-DLISTENER_PORT=%s", fmt.Sprint(i.Lport)),
			fmt.Sprintf("-DREQUEST_PATH_CHECKIN=\"%s\"", requestPathCheckIn),
			fmt.Sprintf("-DREQUEST_PATH_DOWNLOAD=\"%s\"", requestPathDownload),
			fmt.Sprintf("-DREQUEST_PATH_TASKGET=\"%s\"", requestPathTaskGet),
			fmt.Sprintf("-DREQUEST_PATH_TASKRESULT=\"%s\"", requestPathTaskResult),
			fmt.Sprintf("-DREQUEST_PATH_UPLOAD=\"%s\"", requestPathUpload),
			fmt.Sprintf("-DREQUEST_PATH_WEBSOCKET=\"%s\"", requestPathWebSocket),
			"-S.",
			"-Bbuild",
		)
		if err != nil {
			os.Chdir(serverState.CWD)
			return nil, "", fmt.Errorf("create build directory error: %v", err)
		}
		_, err = meta.ExecCommand(
			"cmake",
			"--build", "build",
			"--config", "Release",
			"-j", fmt.Sprint(serverState.NumCPU),
		)
		if err != nil {
			os.Chdir(serverState.CWD)
			return nil, "", fmt.Errorf("build error: %v", err)
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
