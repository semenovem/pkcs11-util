package main

import (
  "flag"
)

type args struct {
  slot string
  pin  string
  lib  string
}

const (
  libOptionUsage  = "PKCS11 library path"
  slotOptionUsage = "HSM slot"
  pinOptionUsage  = "HSM pin"
)

var a = args{}

func init() {
  fl := flag.NewFlagSet("cmd", flag.ContinueOnError)

  fl.StringVar(&a.slot, "slot", a.slot, libOptionUsage)
  fl.StringVar(&a.slot, "s", a.slot, libOptionUsage+" (shorthand)")
  fl.StringVar(&a.pin, "pin", a.slot, slotOptionUsage)
  fl.StringVar(&a.pin, "p", a.slot, slotOptionUsage+" (shorthand)")
  fl.StringVar(&a.lib, "lib", a.slot, pinOptionUsage)
  fl.StringVar(&a.lib, "l", a.slot, pinOptionUsage+" (shorthand)")

  //err := fl.Parse(os.Args[2:])
  //if err != nil {
  //  _, _ = fmt.Fprintf(os.Stderr, "Error parse of arguments: %v\n", err)
  //}

  //fmt.Printf(">>>>>>> args:  %+v \n", a)
}
