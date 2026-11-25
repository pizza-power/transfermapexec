// Command transfermapexec sends a file or a text string from a client to a
// server over one of 32 network methods (raw TCP/TLS/UDP, the web family,
// QUIC, SSH/SFTP, SMB, mail, chat, IoT, DNS tunnelling four ways, monitoring
// protocols, STUN/TURN, WebRTC, ICMP), or over every method in turn, over
// IPv4 and IPv6, and reports which methods got the data through.
//
// The server listens on all of its methods at once. Every transfer carries a
// SHA-256 of its payload, and the server only confirms delivery once the data
// it stored matches it, so "worked" means the bytes arrived intact.
package main

import (
	"fmt"
	"os"
	"time"
)

const (
	appName = "transfermapexec"

	// serverIdleTimeout is how long the server lets a transfer go without
	// moving any data before it gives up on it.
	serverIdleTimeout = 30 * time.Second

	// maxTextDisplay bounds how much of a text payload the server buffers for
	// printing. Larger text is truncated for display but still received in
	// full and checked against its SHA-256.
	maxTextDisplay = 64 << 20 // 64 MiB
)

func main() {
	// quic-go warns when it cannot enlarge its UDP buffers, which is normal on
	// macOS and harmless for transfers of this size.
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "client":
		os.Exit(runClient(os.Args[2:]))
	case "methods":
		printMethods(os.Stdout)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `transfermapexec - send a file or text from client to server over many network methods

Usage:
  transfermapexec server [flags]     receive on every method at once
  transfermapexec client [flags]     send with one method, a list of methods, or -all
  transfermapexec methods            list the methods and their default ports

Run "transfermapexec server -h" or "transfermapexec client -h" for the flags of each subcommand.

Examples:
  transfermapexec server -out ./received
  transfermapexec client -host 192.168.1.50 -method https -file ./report.pdf
  transfermapexec client -host 192.168.1.50 -method dns,icmp,tftp -text "hello"
  transfermapexec client -host 192.168.1.50 -all -file ./report.pdf
  transfermapexec client -host 192.168.1.50,fd00::50 -all -text "v4 and v6"
`)
}
