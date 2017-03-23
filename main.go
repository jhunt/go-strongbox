package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/jhunt/go-cli"
)

/* a single result, from /v1/health/service/vault */
type Result struct {
	Service struct {
		Service string
		Address string
		Port    int
	}
	Checks []struct {
		ServiceName string
		Status      string
	}
}

func bail(w http.ResponseWriter, e error) {
	w.WriteHeader(500)
	w.Header().Add("Content-type", "application/json")

	o := struct {
		Error string `json:"error"`
	}{e.Error()}

	b, err := json.Marshal(o)
	if err != nil {
		fmt.Fprintf(w, `{"error":"srsly bad juju"}`)
		return
	}
	w.Write(b)
}

func usage(prefix string, exit int) {
	if prefix != "" {
		fmt.Fprintf(os.Stderr, "%s\n\n", prefix)
	}
	fmt.Fprintf(os.Stderr, "USAGE: strongbox [options]\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "OPTIONS\n")
	fmt.Fprintf(os.Stderr, "  -b, --bind             IP address and port to bind on.\n")
	fmt.Fprintf(os.Stderr, "                         Omit the address to bind all interfaces.\n")
	fmt.Fprintf(os.Stderr, "                         Defaults to ':8080'\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  -c, --consul           Base URI of the local Consul agent.\n")
	fmt.Fprintf(os.Stderr, "                         Defaults to 'https://127.0.0.1:8500'\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  -C, --ca-certificate   Full path to the certificate for the CA that\n")
	fmt.Fprintf(os.Stderr, "                         has signed the Consul TLS certificates.\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  -N, --no-verify        Don't perform verification of Consul SSL/TLS\n")
	fmt.Fprintf(os.Stderr, "                         certificates (instead of specifying `-C`)\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  -m, --mount            Root (relative) URI at which to mount the\n")
	fmt.Fprintf(os.Stderr, "                         strongbox API.  Defaults to '/strongbox'\n")
	fmt.Fprintf(os.Stderr, "\n")
	os.Exit(exit)
}

var options = struct {
	Help       bool   `cli:"-h, --help"`
	Version    bool   `cli:"-v, --version"`
	Bind       string `cli:"-b, --bind"`
	Consul     string `cli:"-c, --consul"`
	CACert     string `cli:"-C, --ca-certificate, --ca-cert"`
	SkipVerify bool   `cli:"-N, --no-verify"`
	Mount      string `cli:"-m, --mount"`
}{
	Bind:   ":8080",
	Consul: "https://127.0.0.1:8500",
	Mount:  "/strongbox",
}

var Version = ""

func main() {
	command, args, err := cli.Parse(&options)
	if err != nil {
		fmt.Fprintf(os.Stderr, "!!! %s\n", err)
		os.Exit(1)
	}
	if len(args) != 0 {
		usage(fmt.Sprintf("!!! extra arguments found: %s", strings.Join(args, " ")), 1)
	}
	if options.Help || command == "help" {
		usage("", 0)
	}
	if options.Version || command == "version" {
		if Version == "" {
			fmt.Printf("strongbox (development)\n")
		} else {
			fmt.Printf("strongbox v%s\n", Version)
		}
		os.Exit(0)
	}

	rootCAs := x509.NewCertPool()
	if options.CACert == "" {
		rootCAs = nil

	} else {
		n := 0
		raw, err := ioutil.ReadFile(options.CACert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", options.CACert, err)
			os.Exit(2)
		}

		ws := regexp.MustCompile(`^[[:space:]]+`)
		for len(raw) > 0 {
			var b *pem.Block
			b, raw = pem.Decode(raw)
			raw = ws.ReplaceAllLiteral(raw, nil)
			if b == nil {
				fmt.Fprintf(os.Stderr, "%s[%d]: does not look like a PEM-encoded block/file\n",
					options.CACert, n)
				os.Exit(2)
			}
			if b.Type != "CERTIFICATE" {
				fmt.Fprintf(os.Stderr, "found non certificate %v\n", b)
				continue
			}

			ca, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s[%d]: %s\n", options.CACert, n, err)
				os.Exit(2)
			}

			rootCAs.AddCert(ca)
			n++
		}

		if n == 0 {
			fmt.Fprintf(os.Stderr, "%s contains no certificates\n", options.CACert)
			os.Exit(2)
		}
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: options.SkipVerify,
				RootCAs:            rootCAs,
			},
		},
	}

	http.HandleFunc(options.Mount, func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "GET" {
			w.WriteHeader(400)
			return
		}

		if req.URL.Path != options.Mount {
			w.WriteHeader(404)
			fmt.Fprintf(w, "%s not found\n", req.URL.Path)
			return
		}

		question, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/health/service/vault", options.Consul), nil)
		if err != nil {
			bail(w, err)
			return
		}

		answer, err := client.Do(question)
		if err != nil {
			bail(w, err)
			return
		}

		if answer.StatusCode != 200 {
			bail(w, fmt.Errorf("backend service discovery failure"))
			return
		}

		b, err := ioutil.ReadAll(answer.Body)
		if err != nil {
			bail(w, err)
			return
		}

		var rr []Result
		err = json.Unmarshal(b, &rr)
		if err != nil {
			bail(w, err)
			return
		}

		stat := make(map[string]string)
		for _, r := range rr {
			if r.Service.Service != "vault" {
				continue
			}

			for _, c := range r.Checks {
				if c.ServiceName == "vault" {
					k := fmt.Sprintf("https://%s:%d", r.Service.Address, r.Service.Port)
					if c.Status == "passing" {
						stat[k] = "unsealed"
					} else {
						stat[k] = "sealed"
					}
					break
				}
			}
		}

		b, err = json.Marshal(stat)
		if err != nil {
			bail(w, err)
			return
		}

		w.WriteHeader(200)
		w.Header().Add("Content-type", "application/json")
		w.Write(b)
	})

	fmt.Printf("binding %s for inbound requests to %s\n", options.Bind, options.Mount)
	fmt.Printf("(talking to consul at %s)\n", options.Consul)
	http.ListenAndServe(options.Bind, nil)
}
