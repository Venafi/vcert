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

	t.Run("normal", func(t *testing.T) {
		testListener(t, "18443", []string{"test.example.com:18443"}, true)
	})
	t.Run("default port", func(t *testing.T) {
		testListener(t, "443", []string{"example.com"}, true)
	})
	t.Run("two domains", func(t *testing.T) {
		testListener(t, "8443", []string{"example.com", "test.example.com:8443"}, true)
	})
	t.Run("port conflict", func(t *testing.T) {
		testListener(t, "8444", []string{"example.com:443", "test.example.com:8444"}, false)
	})
}

func testListener(t *testing.T, port string, domains []string, success bool) {
	const text = "It works!\n"
	cfg := Config{ConnectorType: endpoint.ConnectorTypeFake}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, text)
	})

	listener := cfg.NewListener(domains...)
	defer listener.Close()
	go http.Serve(listener, mux)
	time.Sleep(time.Millisecond * 100)

	r, err := http.Get("https://localhost:" + port + "/")
	//todo: custom client and check server certificate
	if success && err != nil {
		t.Fatal(err)
	} else if !success && err == nil {
		t.Fatal("test should fail but it doesnt")
	} else if !success {
		return
	}
	if r.StatusCode != 200 {
		t.Fatalf("bad code: %v", r.StatusCode)
	}
	b, _ := ioutil.ReadAll(r.Body)
	if string(b) != text {
		t.Fatalf("bad text: %v", text)
	}

}
