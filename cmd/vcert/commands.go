package main

import "github.com/urfave/cli/v2"

var (
	commandEnroll1 = &cli.Command{
		Name:  "enroll",
		Flags: enrollFlags1,
		Usage: "",
	}
)
