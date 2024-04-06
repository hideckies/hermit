# Configuration

We can edit `config.json` in the Hermit project root for custom server settings.

## host

The C2 server's bind address.  
In most cases, it's no problem that it's `0.0.0.0`.

## port

The C2 server's bind port.  
It's set `9999` by default.

## domains

The C2 server's domains.  
The domains set here are reflected as SANS of certificates.

## listeners.fakeRoutes

We can spoof the paths where the C2 agent sends requests to the listener.  
**Please make sure that the path names are unique,** otherwise unexpected behaviour will occur.
