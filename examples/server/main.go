package main

import (
	"fmt"
	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"io/ioutil"
	"log"
	"net/http"
	"os"
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
	conf := &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeTPP,
		BaseUrl:       os.Getenv("TPP_URL"),
		Credentials: &endpoint.Authentication{
			User:     os.Getenv("TPP_USER"),
			Password: os.Getenv("TPP_PASSWORD")},
		Zone: os.Getenv("TPP_ZONE"),
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
