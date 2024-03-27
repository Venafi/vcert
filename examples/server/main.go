package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/util"
)

const (
	name    = "example-auto-certificate-server"
	version = "v0.0.1"
)

func main() {
	conf := initConfig()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "It works! %v\n", r.Host)
	})
	log.Fatal(http.Serve(conf.NewListener("test.example.com:8443", "example.com"), mux))

}

func initConfig() *vcert.Config {
	userAgent := fmt.Sprintf("%s/%s %s", name, version, util.DefaultUserAgent)
	conf := &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeTPP,
		BaseUrl:       os.Getenv("TPP_URL"),
		Credentials: &endpoint.Authentication{
			User:     os.Getenv("TPP_USER"),
			Password: os.Getenv("TPP_PASSWORD")},
		Zone:      os.Getenv("TPP_ZONE"),
		UserAgent: &userAgent,
	}
	trustBundleFilePath := os.Getenv("TRUST_BUNDLE_PATH")
	if trustBundleFilePath != "" {
		buf, err := ioutil.ReadFile(trustBundleFilePath)
		if err != nil {
			panic(err)
		}
		conf.ConnectionTrust = string(buf)
	}
	return conf
}
