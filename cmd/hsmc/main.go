package main

import (
  "fmt"
  "os"
  "strings"

  "vtb.ru/pkcs11-util/internal/cli/command"
)

const (
  ExitStatusOK = iota
  ExitStatusUsage
  ExitStatusCommandNotFound
  ExitStatusCommandParseError
  ExitStatusCommandVerificationError
  ExitStatusCommandExecutionError
)

func usage() {
  const format = `Usage: %s COMMAND [options]
  COMMAND one of %s
  Type %s COMMAND -help to get usage of the specific command
`
  commands := strings.Join([]string{
    command.Version,
    command.Slots,
    command.List,
    command.Generate,
    command.CertificateRequest,
    command.Destroy,
    command.SetPin,
    command.ImportCertificate,
    command.ImportKey,
  }, "|")
  app := os.Args[0]
  fmt.Printf(format, app, commands, app)
}

var tmp = 2

func main() {
  //if tmp > 0 {
  //  os.Exit(0)
  //}

  if os.Args[1] == "help" || os.Args[1] == "-help" {
    usage()
    os.Exit(ExitStatusUsage)
  }

  cmd := command.Get(os.Args[1])
  if cmd == nil {
    fmt.Fprintf(os.Stderr, "Command not found: %s\n", os.Args[1])
    os.Exit(ExitStatusCommandNotFound)
  }

  if err := cmd.Parse(os.Args[2:]); err != nil {
    os.Exit(ExitStatusCommandParseError)
  }
  if err := cmd.Verify(); err != nil {
    fmt.Fprintf(os.Stderr, "%s\n", err)
    os.Exit(ExitStatusCommandVerificationError)
  }
  if err := cmd.Execute(); err != nil {
    fmt.Fprintf(os.Stderr, "Error: %s\n", err)
    os.Exit(ExitStatusCommandExecutionError)
  }
  os.Exit(ExitStatusOK)
}
