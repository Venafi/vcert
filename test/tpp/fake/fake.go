package fake

import (
	"context"
	"net/http"
	"net/http/httptest"

	"github.com/go-logr/logr"
)

type Fake struct {
	*httptest.Server
}

func New() *Fake {
	mux := http.NewServeMux()
	mux.HandleFunc("/vedauth/authorize/oauth", func(w http.ResponseWriter, req *http.Request) {
		defer req.Body.Close()
		w.Write([]byte("{}"))
		return
	})
	ts := httptest.NewUnstartedServer(mux)
	return &Fake{
		Server: ts,
	}
}

func (o *Fake) Start(ctx context.Context) {
	log := logFromContext(ctx)
	log.V(1).Info("starting")
	o.Server.StartTLS()
}

func (o *Fake) Close(ctx context.Context) {
	log := logFromContext(ctx)
	log.V(1).Info("stopping")
	o.Server.Close()
}

func logFromContext(ctx context.Context) logr.Logger {
	log, err := logr.FromContext(ctx)
	if err != nil {
		panic(err)
	}
	return log
}
