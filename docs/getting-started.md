# Getting Started

## 1. Install Hermit

Please see [the installation page](installation.md).

## 2. Start C2 Server

### 1. Set up the Configuration

The `config.json` is in the project root. You can edit it for setting the bind address/port, domains, etc. Hermit automatically reads this configurations when starting the server.  

If you're not particular about it, there's no problem leaving it as is.

### 2. Start the C2 server and console

Simply execute the `hermit` command in the project directory where you've installed **Hermit**.  

```sh
./hermit
# or
./hermit server
```

Hermit automatically reads the `./config.json` file and setup the configuration from the file.  
You can also specify the config file path as below:

```sh
./hermit -c /path/to/config.json
```

Now the C2 server and console start and you can do all operations for the Hermit C2.  

- As solo, you can use it as is in this server console.  
- As team, proceed below to run the C2 client for each operator.

### 3. Transfer the Client Config File

If you would like to use Hermit as team and use C2 client, please do the follow:  

1. Once the C2 server starts, the client config file is generated at `$HOME/.hermit/server/configs/client-config-<operator>.json`.  
2. Transfer this file to the C2 client computer. 
3. To generate a new config file for another operator, run the `client-config gen` command on the C2 server console.

## 3. Start C2 Client

### 1. Set up the Configuration

Before starting the C2 client, please follow the previous **"3. Transfer the Client Config File"** section. 
You can edit the following config as needed:

- operator

### 2. Start the C2 client

Simply run the following command with specifying the `client-config-<operator>.json`.

```sh
./hermit-client -c /path/to/client-config-<operator>.json
```

## 4. More Deeper...

Please see [the Tutorial: Simple Implant Beacon](tutorials/simple-implant-beacon.md).