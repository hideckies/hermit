# Agent Mode

We can switch to the agent mode with `agent use <agent-id>` command in the C2 server console.  
This feature can be used after C2 agents connected to listeners.

Once the agent mode activated, our prompt looks like below:

```sh
Hermit [agent-abcd] >
```

As seen above, `[agent-abcd]` string is added.  

## What Difference Between Normal Mode and Agent Mode?

In Agent mode, we can use most of the commands found in Normal mode, as well as send [tasks](./task.md) to C2 agents and see loot that gained by task results.  

To see all commands available, run `?`, `help` or `help <command>`.