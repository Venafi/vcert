package vcert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/venafi/fake"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

func TestConfig_NewListener(t *testing.T) {

	t.Run("normal", func(t *testing.T) {
		testListener(t, "localhost:18443", []string{"localhost:18443"}, true)
	})
	t.Run("default port", func(t *testing.T) {
		testListener(t, "localhost:443", []string{"localhost"}, true)
	})
	t.Run("two domains", func(t *testing.T) {
		testListener(t, "localhost:8443", []string{"localhost", "test.example.com:8443"}, true)
	})
	t.Run("port conflict", func(t *testing.T) {
		testListener(t, "localhost:8444", []string{"localhost:443", "test.example.com:8444"}, false)
	})
	t.Run("invalid hostname", func(t *testing.T) {
		testListener(t, "localhost:8445", []string{"example.com:8445"}, false)
	})
}

func testListener(t *testing.T, host string, domains []string, success bool) {
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
	client := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{}}}
	_, err := client.Get("https://" + host + "/")
	if err == nil {
		t.Fatal("without trust bundle connection should fail")
	}
	connectionTrustBundle := x509.NewCertPool()
	connectionTrustBundle.AppendCertsFromPEM([]byte(fake.CaCertPEM))
	client = http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: connectionTrustBundle}}}
	r, err := client.Get("https://" + host + "/")
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
