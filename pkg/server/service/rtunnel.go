package service

import (
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

func handleConnection(local net.Conn, remoteEndpoint string) {
	defer local.Close()

	remote, err := net.Dial("tcp", remoteEndpoint)
	if err != nil {
		return
	}
	defer remote.Close()

	go io.Copy(remote, local)
	io.Copy(local, remote)
}

func handleChannel(newChannel ssh.NewChannel, rhost string, rport uint16) {
	if newChannel.ChannelType() != "direct-tcpip" {
		newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		return
	}

	channel, _, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer channel.Close()

	// Get remote address and handle connection
	remoteAddr := fmt.Sprintf("%s:%s:%d", newChannel.ExtraData()[4:], rhost, rport)
	remote, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		return
	}
	defer remote.Close()

	go io.Copy(remote, channel)
	io.Copy(channel, remote)
}

func RTunnelListenerStart(lhost string, lport uint16, rhost string, rport uint16) error {
	hostKayPath := "/path/to/ssh/hostkey"

	hostKey, err := os.ReadFile(hostKayPath)
	if err != nil {
		return err
	}

	signer, err := ssh.ParsePrivateKey(hostKey)
	if err != nil {
		return err
	}

	config := &ssh.ServerConfig{
		NoClientAuth: true, // TODO: Implement authentication.
	}
	config.AddHostKey(signer)

	sshServerPort := 2222
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", lhost, sshServerPort))
	if err != nil {
		return err
	}
	defer lis.Close()

	for {
		conn, err := lis.Accept()
		if err != nil {
			return err
		}

		go func(c net.Conn) {
			defer c.Close()

			// SSH handshake
			sshConn, chans, reqs, err := ssh.NewServerConn(c, config)
			if err != nil {
				return
			}
			defer sshConn.Close()

			// Discard global requests.
			go ssh.DiscardRequests(reqs)

			// Accept channel requests.
			for newChannel := range chans {
				go handleChannel(newChannel, rhost, rport)
			}

		}(conn)
	}

	return nil
}
