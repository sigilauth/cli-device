package main

import (
	"fmt"
	"os"
)

const version = "0.1.0"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("sigil-device v%s\n", version)
		os.Exit(0)
	}

	if len(os.Args) > 1 && (os.Args[1] == "--help" || os.Args[1] == "-h") {
		printHelp()
		os.Exit(0)
	}

	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	var err error
	switch command {
	case "init":
		err = cmdInit(args)
	case "pair":
		err = cmdPair(args)
	case "register":
		err = cmdRegister(args)
	case "listen":
		err = cmdListen(args)
	case "respond":
		err = cmdRespondWrapper(args)
	case "mpa-respond":
		err = cmdMPARespondWrapper(args)
	case "decrypt":
		err = cmdDecryptWrapper(args)
	case "crypto-sign":
		err = cmdCryptoSign(args)
	case "pair-handshake":
		err = cmdPairHandshake(args)
	case "envelope-encrypt":
		err = cmdEnvelopeEncrypt(args)
	case "envelope-decrypt":
		err = cmdEnvelopeDecrypt(args)
	case "whoami":
		err = cmdWhoamiWrapper(args)
	case "unpair":
		err = cmdUnpairWrapper(args)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Printf("sigil-device v%s\n\n", version)
	fmt.Println("Usage: sigil-device <command> [args]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  init         Initialize device identity")
	fmt.Println("  pair         Pair with Sigil server (SIGIL-CONV-V1 handshake)")
	fmt.Println("  register     Register with push relay")
	fmt.Println("  listen       Listen for push notifications")
	fmt.Println("  respond      Respond to auth challenge")
	fmt.Println("  mpa-respond  Respond to MPA challenge")
	fmt.Println("  decrypt      Decrypt ECIES payload")
	fmt.Println("  crypto-sign       Sign message for test harness (auth/mpa/decrypt)")
	fmt.Println("  pair-handshake    Derive session pictogram (test harness)")
	fmt.Println("  envelope-encrypt  Create ECIES envelope (test harness)")
	fmt.Println("  envelope-decrypt  Decrypt ECIES envelope (test harness)")
	fmt.Println("  whoami            Display device identity")
	fmt.Println("  unpair            Remove device identity")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --help, -h   Show this help message")
	fmt.Println("  --version, -v  Show version")
}
