package main

import (
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

var (
	listenAddr      = ":8080"
	allowedDomains  []string
	authUser        string
	authPass        string
)

func main() {
	// Konfiguráció betöltése környezeti változókból
	authUser = os.Getenv("PROXY_USER")
	authPass = os.Getenv("PROXY_PASS")
	rawDomains := os.Getenv("ALLOWED_DOMAINS")

	if authUser == "" || authPass == "" || rawDomains == "" {
		log.Fatal("Missing required environment variables: PROXY_USER, PROXY_PASS, ALLOWED_DOMAINS")
	}

	allowedDomains = parseDomains(rawDomains)
	log.Printf("Allowed domains: %v", allowedDomains)

	// HTTP szerver indítása
	server := &http.Server{
		Addr:    listenAddr,
		Handler: http.HandlerFunc(handleRequest),
	}

	log.Println("Proxy listening on", listenAddr)
	log.Fatal(server.ListenAndServe())
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Autentikáció
	if !checkAuth(r) {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Restricted\"")
		http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
		log.Printf(`{"event":"auth_fail","client":"%s"}`, r.RemoteAddr)
		return
	}

	// Csak CONNECT metódus engedélyezett
	if r.Method != http.MethodConnect {
		http.Error(w, "Only CONNECT method allowed", http.StatusMethodNotAllowed)
		log.Printf(`{"event":"invalid_method","method":"%s","client":"%s"}`, r.Method, r.RemoteAddr)
		return
	}

	// Cél domain ellenőrzése
	host := r.Host
	if !isAllowedDomain(host) {
		http.Error(w, "Domain not allowed", http.StatusForbidden)
		log.Printf(`{"event":"domain_denied","client":"%s","target":"%s"}`, r.RemoteAddr, host)
		return
	}

	log.Printf(`{"event":"connect","client":"%s","target":"%s"}`, r.RemoteAddr, host)

	// TCP kapcsolat a célhoz
	destConn, err := net.Dial("tcp", host)
	if err != nil {
		http.Error(w, "Could not connect to destination", http.StatusServiceUnavailable)
		log.Printf(`{"event":"dial_failed","target":"%s","error":"%s"}`, host, err)
		return
	}
	defer destConn.Close()

	// HTTP válasz a kliensnek
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijacking failed", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	// Adatforgalom továbbítása oda-vissza
	go io.Copy(destConn, clientConn)
	io.Copy(clientConn, destConn)
}

func checkAuth(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return false
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return false
	}
	pair := strings.SplitN(string(payload), ":", 2)
	return len(pair) == 2 && pair[0] == authUser && pair[1] == authPass
}

func isAllowedDomain(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	host = strings.ToLower(host)

	for _, domain := range allowedDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func parseDomains(raw string) []string {
	parts := strings.Split(raw, ",")
	var cleaned []string
	for _, p := range parts {
		d := strings.TrimSpace(p)
		if d != "" {
			cleaned = append(cleaned, strings.ToLower(d))
		}
	}
	return cleaned
}
