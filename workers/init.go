package workers

import (
	"fmt"
	"os"

	"github.com/miekg/dns"
)

// dns server from config. write once on startup
var ResolverConfig *dns.ClientConfig = nil

const ENV_RESOLV_PATH= "DNSSCAN_RESOLV_PATH"
const DEFAULT_RESOLV_PATH = "resolv.conf"

func Init() error {
	path := os.Getenv(ENV_RESOLV_PATH)
	if path == "" {
		fmt.Printf(
			"Env variable '%s' not set, falling back to '%s'\n",
			ENV_RESOLV_PATH,
			DEFAULT_RESOLV_PATH,
		)
	path = DEFAULT_RESOLV_PATH
	}

	cfg, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return err
	}

	ResolverConfig = cfg
	return nil
}
