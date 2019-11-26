package vcert

import (
	"fmt"
	"github.com/Venafi/vcert/pkg/endpoint"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

func TestConfig_NewListener(t *testing.T) {

	testListener(t, "18443", []string{"test.example.com:18443"})
	testListener(t, "443", []string{"example.com"})
	testListener(t, "8443", []string{"example.com", "test.example.com:8443"})
}

func testListener(t *testing.T, port string, domains []string) {
	const text = "It works!\n"
	cfg := Config{ConnectorType: endpoint.ConnectorTypeFake}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, text)
	})

	listener := cfg.NewListener(domains...)
	go http.Serve(listener, mux)
	time.Sleep(time.Millisecond * 100)

	r, err := http.Get("https://localhost:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != 200 {
		t.Fatalf("bad code: %v", r.StatusCode)
	}
	b, _ := ioutil.ReadAll(r.Body)
	if string(b) != text {
		t.Fatalf("bad text: %v", text)
	}
	listener.Close()
}
