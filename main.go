package main

import (
	"context"
	"flag"
	"github.com/Keyfactor/terraform-provider-keyfactor/keyfactor"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"log"
)

//go:generate terraform fmt -recursive ./examples/

// Run the docs generation tool, check its repository for more information on how it works and how docs
// can be customized.
//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs

// To run these tools, run 'go generate'

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "keyfactor.com/keyfactordev/keyfactor",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), keyfactor.New, opts)

	if err != nil {
		log.Fatal(err.Error())
	}
}
