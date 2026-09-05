//go:build ignore

package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from Legacy Service! Negotiated Host: %s\n", r.Host)
	})

	fmt.Println("Legacy HTTP Upstream running on http://127.0.0.1:8080...")
	http.ListenAndServe("127.0.0.1:8080", nil)
}
