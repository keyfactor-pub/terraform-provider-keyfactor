package main

import (
	"context"
	"flag"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/keyfactor-pub/terraform-provider-keyfactor/keyfactor"
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
		version = keyfactor.VERSION
	}

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	address := "github.com/keyfactor-pub/keyfactor"
	if debug {
		address = "keyfactor.com/keyfactor/keyfactor"
	}
	opts := providerserver.ServeOpts{
		Address:         address,
		Debug:           debug,
		ProtocolVersion: 6,
	}

	err := providerserver.Serve(context.Background(), keyfactor.New, opts)

	if err != nil {
		log.Fatal(err.Error())
	}
}
