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

var Version = ""

func main() {
	/* for now, bind *:8080 and connect to 127.0.0.1:8500 */
	bind := ":8080"
	consul := "https://127.0.0.1:8500"
	cacertfile := ""
	verifytls := true
	mount := "/strongbox"

	args := os.Args[1:]
	for len(args) > 0 {
		if args[0] == "-h" || args[0] == "--bind" || args[0] == "help" {
			usage("", 0)
		}

		if args[0] == "-v" || args[0] == "--version" || args[0] == "version" {
			if Version == "" {
				fmt.Printf("strongbox (development)\n")
			} else {
				fmt.Printf("strongbox v%s\n", Version)
			}
			os.Exit(0)
		}

		if args[0] == "-b" || args[0] == "--bind" {
			if len(args) < 2 || args[1] == "" {
				usage("Missing required value for --bind argument", 1)
			}

			bind = args[1]
			args = args[2:]
			continue
		}

		if args[0] == "-c" || args[0] == "--consul" {
			if len(args) < 2 || args[1] == "" {
				usage("Missing required value for --consul argument", 1)
			}

			consul = args[1]
			args = args[2:]
			continue
		}

		if args[0] == "-C" || args[0] == "--ca-cert" || args[0] == "--ca-certificate" {
			if len(args) < 2 || args[1] == "" {
				usage("Missing required value for --ca-certificate argument", 1)
			}

			cacertfile = args[1]
			args = args[2:]
			continue
		}

		if args[0] == "-N" || args[0] == "--no-verify" {
			verifytls = false
			args = args[1:]
			continue
		}

		if args[0] == "-m" || args[0] == "--mount" {
			if len(args) < 2 || args[1] == "" {
				usage("Missing required value for --mount argument", 1)
			}

			mount = args[1]
			args = args[2:]
			continue
		}

		usage(fmt.Sprintf("Unrecognized command-line flag or argument, '%s'", args[0]), 1)
	}

	rootCAs := x509.NewCertPool()
	if cacertfile == "" {
		rootCAs = nil

	} else {
		n := 0
		raw, err := ioutil.ReadFile(cacertfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", cacertfile, err)
			os.Exit(2)
		}

		for len(raw) > 0 {
			var b *pem.Block
			b, raw = pem.Decode(raw)
			if b.Type != "CERTIFICATE" {
				continue
			}

			ca, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s[%d]: %s\n", cacertfile, n, err)
				os.Exit(2)
			}

			rootCAs.AddCert(ca)
			n++
		}

		if n == 0 {
			fmt.Fprintf(os.Stderr, "%s contains no certificates\n")
			os.Exit(2)
		}
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !verifytls,
				RootCAs:            rootCAs,
			},
		},
	}

	http.HandleFunc(mount, func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "GET" {
			w.WriteHeader(400)
			return
		}

		if req.URL.Path != mount {
			w.WriteHeader(404)
			fmt.Fprintf(w, "%s not found\n", req.URL.Path)
			return
		}

		question, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/health/service/vault", consul), nil)
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

	http.ListenAndServe(bind, nil)
}
