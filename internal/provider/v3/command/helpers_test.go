package command

import (
	"regexp"
)

var emptyCertRequestErrRegex = regexp.MustCompile(`.*Unable to find certificate  in Keyfactor Command`)
var invalidAgentRequestErrRegex = regexp.MustCompile(`.*Invalid Agent Identifier*`)
