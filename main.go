package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/k0kubun/pp"
)

const (
	defaultConcurrency = 20
	defaultDebugMode   = false
	errExpiringShortly = "%s: ** '%s' (S/N %X) expires in %d hours! **"
	errExpiringSoon    = "%s: '%s' (S/N %X) expires in roughly %d days."
	errSunsetAlg       = "%s: '%s' (S/N %X) expires after the sunset date for its signature algorithm '%s'."
	DEFAULT_PORTS_CSV  = `443,`
)

var (
	ports_to_check = []int64{}
	DEBUG_MODE     = defaultDebugMode
	debugMode      = flag.Bool("debug", DEBUG_MODE, "Enable Debug Mode.")
	hostsFile      = flag.String("hosts", "", "The path to the file containing a list of hosts to check.")
	portsCsv       = flag.String("ports", DEFAULT_PORTS_CSV, "Comma Seperated list of ports to check.")
	warnYears      = flag.Int("years", 0, "Warn if the certificate will expire within this many years.")
	warnMonths     = flag.Int("months", 0, "Warn if the certificate will expire within this many months.")
	warnDays       = flag.Int("days", 0, "Warn if the certificate will expire within this many days.")
	checkSigAlg    = flag.Bool("check-sig-alg", true, "Verify that non-root certificates are using a good signature algorithm.")
	concurrency    = flag.Int("concurrency", defaultConcurrency, "Maximum number of hosts to check at once.")

	DIAL_TIMEOUT          = 1 * time.Second
	tls_connection_config = &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				DNSName:       cs.ServerName,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		},
	}
)

type sigAlgSunset struct {
	name      string    // Human readable name of signature algorithm
	sunsetsAt time.Time // Time the algorithm will be sunset
}

var sunsetSigAlgs = map[x509.SignatureAlgorithm]sigAlgSunset{
	x509.MD2WithRSA: sigAlgSunset{
		name:      "MD2 with RSA",
		sunsetsAt: time.Now(),
	},
	x509.MD5WithRSA: sigAlgSunset{
		name:      "MD5 with RSA",
		sunsetsAt: time.Now(),
	},
	x509.SHA1WithRSA: sigAlgSunset{
		name:      "SHA1 with RSA",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.DSAWithSHA1: sigAlgSunset{
		name:      "DSA with SHA1",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.ECDSAWithSHA1: sigAlgSunset{
		name:      "ECDSA with SHA1",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
}

type certErrors struct {
	commonName string
	errs       []error
}

type checked_host_port_result struct {
	Port       int64
	Host       string
	Connected  bool
	DurationMs int64
	Dialed     string
}

type hostResult struct {
	host               string
	err                error
	certs              []certErrors
	open_ports         []int
	checked_host_ports []*checked_host_port_result
}

func checkHost(host string) (result hostResult) {
	result = hostResult{
		host:               host,
		certs:              []certErrors{},
		open_ports:         []int{},
		checked_host_ports: []*checked_host_port_result{},
	}
	for _, check_port := range ports_to_check {
		cp := &checked_host_port_result{
			Host:   host,
			Port:   check_port,
			Dialed: fmt.Sprintf("%s:%d", host, check_port),
		}
		started := time.Now()
		conn, err := net.DialTimeout("tcp", cp.Dialed, DIAL_TIMEOUT)
		cp.DurationMs = time.Since(started).Milliseconds()
		if err != nil {
			cp.Connected = false
			result.err = err
		} else {
			cp.Connected = true
			conn.Close()
			tls_conn, err := tls.Dial(`tcp`, cp.Dialed, nil)
			if err == nil {
				timeNow := time.Now()
				for _, chain := range tls_conn.ConnectionState().VerifiedChains {
					for certNum, cert := range chain {
						cErrs := []error{}
						expiresIn := int64(cert.NotAfter.Sub(timeNow).Hours())
						if timeNow.AddDate(*warnYears, *warnMonths, *warnDays).After(cert.NotAfter) {
							if expiresIn <= 48 {
								cErrs = append(cErrs, fmt.Errorf(errExpiringShortly, host, cert.Subject.CommonName, cert.SerialNumber, expiresIn))
							} else {
								cErrs = append(cErrs, fmt.Errorf(errExpiringSoon, host, cert.Subject.CommonName, cert.SerialNumber, expiresIn/24))
							}
						}

						if alg, exists := sunsetSigAlgs[cert.SignatureAlgorithm]; *checkSigAlg && exists && certNum != len(chain)-1 {
							if cert.NotAfter.Equal(alg.sunsetsAt) || cert.NotAfter.After(alg.sunsetsAt) {
								cErrs = append(cErrs, fmt.Errorf(errSunsetAlg, host, cert.Subject.CommonName, cert.SerialNumber, alg.name))
							}
						}

						result.certs = append(result.certs, certErrors{
							commonName: cert.Subject.CommonName,
							errs:       cErrs,
						})
						if DEBUG_MODE {
							fmt.Printf("%s on %s (%d errors) expires in %d hours.\n", cert.Subject.CommonName, host, len(cErrs), expiresIn)
						}
					}
				}
			}
		}
		result.checked_host_ports = append(result.checked_host_ports, cp)
	}
	return
}

func processQueue(done <-chan struct{}, hosts <-chan string, results chan<- hostResult) {
	for host := range hosts {
		select {
		case results <- checkHost(host):
		case <-done:
			return
		}
	}
}

func main() {
	flag.Parse()
	DEBUG_MODE = *debugMode

	for _, p := range strings.Split(*portsCsv, `,`) {
		pi, err := strconv.ParseInt(p, 10, 0)
		if err == nil && pi > 0 && pi < 65536 {
			ports_to_check = append(ports_to_check, pi)
		}
	}

	if len(*hostsFile) == 0 {
		fmt.Print("Must specify host file path\n")
		flag.Usage()
		return
	}

	if *warnYears < 0 {
		*warnYears = 0
	}
	if *warnMonths < 0 {
		*warnMonths = 0
	}
	if *warnDays < 0 {
		*warnDays = 0
	}
	if *warnYears == 0 && *warnMonths == 0 && *warnDays == 0 {
		*warnDays = 30
	}
	if *concurrency < 0 {
		*concurrency = defaultConcurrency
	}

	processHosts()

}

type StrSlice []string

func (list StrSlice) Has(a string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func processHosts() {
	started := time.Now()
	done := make(chan struct{})
	defer close(done)
	hosts := queueHosts(done)
	results := make(chan hostResult)
	var wg sync.WaitGroup

	wg.Add(*concurrency)
	for i := 0; i < *concurrency; i++ {
		go func() {
			processQueue(done, hosts, results)
			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	checked_hosts := StrSlice{}
	checked_hosts_qty := 0
	checked_certs_qty := 0
	found_cert_errs_qty := 0
	connected_ports_qty := 0
	checked_ports_qty := 0
	results_qty := 0
	for r := range results {
		results_qty = results_qty + 1
		if !checked_hosts.Has(r.host) {
			checked_hosts_qty = checked_hosts_qty + 1
			checked_hosts = append(checked_hosts, r.host)
		}
		checked_ports_qty = checked_ports_qty + 1
		if r.err != nil {
			log.Printf("Host %s Connection Error: %v\n", r.host, r.err)
		} else {
			connected_ports_qty = connected_ports_qty + 1
			for cq, cert := range r.certs {
				checked_certs_qty = checked_certs_qty + 1
				ns := pp.Sprintf("\n      %s\n", cert)
				if DEBUG_MODE {
					fmt.Printf("	[processHosts] cert #%d: %s\n", cq, ns)
				}
				for _, err := range cert.errs {
					found_cert_errs_qty = found_cert_errs_qty + 1
					log.Printf("  %s :: Certificate Error (CN:%s): %s\n", r.host, cert.commonName, err.Error())
				}
			}
		}
	}
	dur := time.Since(started)
	msg := fmt.Sprintf("\n ** Found %d Issues from %d results among %d certs from %d/%d ports and %d hosts in %dms.\n", found_cert_errs_qty, results_qty, checked_certs_qty, connected_ports_qty, checked_ports_qty, checked_hosts_qty, dur.Milliseconds())
	fmt.Printf("%s\n", msg)
}

func queueHosts(done <-chan struct{}) <-chan string {
	hosts := make(chan string)
	go func() {
		defer close(hosts)

		fileContents, err := ioutil.ReadFile(*hostsFile)
		if err != nil {
			return
		}
		lines := strings.Split(string(fileContents), "\n")
		for _, line := range lines {
			host := strings.TrimSpace(line)
			if len(host) == 0 || host[0] == '#' {
				continue
			}
			select {
			case hosts <- host:
			case <-done:
				return
			}
		}
	}()
	return hosts
}
