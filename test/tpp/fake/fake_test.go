package fake_test

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/Venafi/vcert/v4/test/tpp/fake"
)

func TestFake(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)

	grp, ctx := errgroup.WithContext(ctx)
	t.Cleanup(func() {
		require.NoError(t, grp.Wait())
	})

	log := testr.NewWithOptions(t, testr.Options{
		Verbosity: 10,
	})
	ctx = logr.NewContext(ctx, log)

	const (
		tppUsername = "user1"
		tppPassword = "password1"
		tppClientID = "test-application"
		tppZone     = "zone1"
	)
	s := fake.New(log)
	s.WithUser(tppUsername, tppPassword).
		WithApplication(
			"vcert-sdk",
			"certificate:discover,manage,revoke;configuration:manage;ssh:manage",
			tppUsername,
		).
		WithApplication(
			tppClientID,
			"certificate:discover,manage,revoke",
			tppUsername,
		)

	s.Start()
	t.Cleanup(s.Close)

	cmd := exec.CommandContext(ctx, os.Getenv("MAKE"), "tpp_test")
	cmd.Dir = "../../.."
	cmd.Env = append(
		os.Environ(),
		"TPP_URL="+s.URL,
		"TPP_USER="+tppUsername,
		"TPP_PASSWORD="+tppPassword,
		"TPP_ZONE="+tppZone,
		"CLIENT_ID="+tppClientID,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	require.NoError(t, err)
}
