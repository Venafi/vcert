package main

import (
	"k8s.io/klog/v2"

	"github.com/Venafi/vcert/v4/test/tpp/fake"
	"github.com/Venafi/vcert/v4/test/tpp/signals"
)

func main() {
	ctx := signals.SetupSignalHandler()
	log := klog.NewKlogr()
	tpp := fake.New(log)
	tpp.Start()
	log.Info("started", "url", tpp.URL)
	<-ctx.Done()
	tpp.Close()
}
