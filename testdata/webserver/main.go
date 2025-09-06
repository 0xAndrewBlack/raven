package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello from the RISC-V runtime!")
}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("Server in ascolto sulla porta 8080...")
	http.ListenAndServe(":8080", nil)
}
