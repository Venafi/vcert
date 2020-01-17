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
		Flags: getcredFlags1,
		Usage: "To obtain a new token for authentication",
	}
	commandGenCSR1 = &cli.Command{
		Name:  "gencsr",
		Flags: genCsrFlags1,
		Usage: "To generate a certificate signing request (CSR)",
	}
	commandPickup1 = &cli.Command{
		Name:  "pickup",
		Flags: pickupFlags1,
		Usage: "To retrieve a certificate",
	}
	commandRevoke1 = &cli.Command{
		Name:  "revoke",
		Flags: revokeFlags1,
		Usage: "To revoke a certificate",
	}
	commandRenew1 = &cli.Command{
		Name:  "renew",
		Flags: renewFlags1,
		Usage: "To renew a certificate",
	}
)
