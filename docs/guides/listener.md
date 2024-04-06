# Listener

The `listener` command manages for the listener create/start/stop/delete.  

For usage, run `help listener`, `help listener <subcommand>`.

## `listener new`

Creates a new listener and start it.  
If we simply run the `lisetner new` command without flags, the address is set from the network interface (`eth0` or `ens33`) and the port is generated randomly between `49152` and `65535`. And domains are set from `config.json` setting.

### Custom URL & Domains

We can specify the custom URL and domains (separate with `,` for multiple domains).

```sh title="Hermit C2 Server Console"
Hermit > listener new -u https://172.12.34.56:4443 --d hermit.evil,hacker.tokyo
```

## `listener start <ID>`

Starts a specified listener by ID.  

## `listener stop <ID>`

Stops a specified listener by ID.

## `listener delete <ID>`

Deletes a specified listener by ID.

## `listener list`, `listeners`

Lists all listeners available.

## `listener info <ID>`

Prints a listener detailed information.

## `listener payloads <ID>`

Lists and manages payloads hosted on a specified listener by ID.  
On the select menu after run this command, we can select the payload and delete it.

