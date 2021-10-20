package main

import (
	"context"
	"flag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
	"log"

	"terraform-provider-keyfactor/keyfactor"
)

// "github.com/m8rmclaren/terraform-provider-keyfactor/keyfactor" eventually

func main() {
	var debugMode bool
	flag.BoolVar(&debugMode, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := &plugin.ServeOpts{
		ProviderFunc: func() *schema.Provider {
			return keyfactor.Provider()
		},
	}

	if debugMode {
		err := plugin.Debug(context.Background(), "keyfactor.com/keyfactordev/keyfactor", opts)
		if err != nil {
			log.Fatal(err.Error())
		}
		return
	}

	plugin.Serve(opts)
}
