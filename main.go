package main

import (
	"context"
	"flag"
	"github.com/getsentry/sentry-go"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	v3 "github.com/keyfactor-pub/terraform-provider-keyfactor/internal/provider/v3/command"
	"log"
	"os"
)

// Run "go generate" to format example terraform files and generate the docs for the registry/website

// If you do not have terraform installed, you can remove the formatting command, but its suggested to
// ensure the documentation is formatted properly.
//go:generate terraform fmt -recursive ./examples/

// Run the docs generation tool, check its repository for more information on how it works and how docs
// can be customized.

// To run these tools, run 'go generate'

func main() {
	var debug bool

	version := os.Getenv("GITHUB_REF_NAME")
	if version == "" {
		version = v3.VERSION
	}

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	if !debug {
		envDebug := os.Getenv("DEBUG")
		if envDebug != "" && envDebug != "false" {
			debug = true
		}
	}

	address := "github.com/keyfactor-pub/keyfactor"
	if debug {
		address = "keyfactor.com/command/v3"
		configSentry()
	}
	opts := providerserver.ServeOpts{
		Address: address,
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), v3.New(version), opts)

	if err != nil {
		log.Fatal(err.Error())
	}
}

func configSentry() {
	err := sentry.Init(sentry.ClientOptions{
		Dsn: "https://814b0846082d547816b62ebab2b59aa0@o4505352704360448.ingest.sentry.io/4506395161067520",
		// Set TracesSampleRate to 1.0 to capture 100%
		// of transactions for performance monitoring.
		// We recommend adjusting this value in production,
		TracesSampleRate: 1.0,
	})
	if err != nil {
		log.Fatalf("sentry.Init: %s", err)
	}
}
