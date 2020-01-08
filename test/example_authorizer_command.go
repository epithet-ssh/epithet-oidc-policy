package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/epithet-ssh/epithet-oidc-policy/pkg/authorizer"
)

func main() {
	user := os.Args[1]

	groups := []string{
		"group2",
		user,
	}
	expr, _ := strconv.Atoi(os.Args[2])
	expiration := time.Duration(expr) * time.Second
	extensions := map[string]string{
		"permit-agent-forwarding": "",
		"permit-pty":              "",
		"permit-user-rc":          "",
	}

	a := authorizer.Authorization{
		Groups:     groups,
		Expiration: expiration,
		Extensions: extensions,
	}
	output, _ := json.Marshal(a)
	fmt.Printf(string(output))
}
