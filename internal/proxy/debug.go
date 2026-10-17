package proxy

import (
	"fmt"
	"os"
)

func proxyDebugf(format string, args ...any) {
	if os.Getenv("NETINSPECT_PROXY_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[proxy-debug] "+format+"\n", args...)
	}
}
