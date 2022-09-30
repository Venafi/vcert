package fake_test

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/Venafi/vcert/v4/test/tpp/fake"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/require"
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

	s := fake.New()
	s.Start(ctx)
	t.Cleanup(func() { s.Close(ctx) })

	cmd := exec.CommandContext(ctx, "make", "tpp_test")
	cmd.Dir = "../../.."
	cmd.Env = append(
		os.Environ(),
		"TPP_URL="+s.URL,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	require.NoError(t, err)
}
