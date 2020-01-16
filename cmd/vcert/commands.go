package main

import "github.com/urfave/cli/v2"

var (
	commandEnroll1 = &cli.Command{
		Name:  "enroll",
		Flags: enrollFlags1,
		Usage: "To enroll a certificate,",
	}
	commandGetcred1 = &cli.Command{
		Name:  "getcred",
		Usage: "To obtain a new token for authentication",
	}
	commandGenCSR1 = &cli.Command{
		Name:  "gencsr",
		Usage: "To generate a certificate signing request (CSR)",
	}
	commandPickup1 = &cli.Command{
		Name:  "pickup",
		Usage: "To retrieve a certificate",
	}
	commandRevoke1 = &cli.Command{
		Name:  "revoke",
		Usage: "To revoke a certificate",
	}
	commandRenew1 = &cli.Command{
		Name:  "renew",
		Usage: "To renew a certificate",
	}
)
