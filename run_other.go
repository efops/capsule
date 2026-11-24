//go:build !linux

package main

import (
	"errors"
	"time"
)

var errLinuxOnly = errors.New("this needs a Linux kernel; keygen, seal, approve, verify, card, host, log and receipt work here")

func initCapsule() error         { return errLinuxOnly }
func cmdRun([]string) error      { return errLinuxOnly }
func cmdPs() error               { return errLinuxOnly }
func cmdKill([]string) error     { return errLinuxOnly }
func cmdResize([]string) error   { return errLinuxOnly }
func cmdPrune([]string) error    { return errLinuxOnly }
func cmdVolumes([]string) error  { return errLinuxOnly }
func cmdIdentity([]string) error { return errLinuxOnly }

func carryOut(order, time.Duration) (string, error) { return "", errLinuxOnly }
func enterCapsule() error                           { return errLinuxOnly }
func cmdHelper() error                              { return errLinuxOnly }
