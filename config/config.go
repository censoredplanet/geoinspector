package config

import "flag"

var InputURLFile string
var InputDNSResolversFile string
var InputConnFile string
var OutputDNSFile string
var ControlDNSFile string
var DNSParsedOutput string
var OutputConnFile string
var OutputFailedConnFile string
var AsnMmdb string
var Module string
var NumWorkers int
var NumQueryWorkers int
var NumRedirects int
var Srcip string
var IgnoreLocalResolvers bool

var WhoamiEndpoints = [...]string{
	"o-o.myaddr.l.google.com",
	"whoami.cloudflare.com",
	"whoami.ipv6.akahelp.net",
	"whoami.ipv4.akahelp.net",
	"whoami.ds.akahelp.net",
}

func init() {
	flag.StringVar(&InputURLFile, "input-url-file", "", "Input list of URLs to test (required)")
	flag.StringVar(&AsnMmdb, "asn-mmdb", "", "Path to Maxmind ASN mmdb (required)")
	flag.StringVar(&InputDNSResolversFile, "input-resolver-file", "", "Input list of resolvers to send queries to")
	flag.StringVar(&InputConnFile, "input-conn-file", "", "Input list of servers to perform a TCP connection to and send data (required if not running in full mode)")
	flag.StringVar(&OutputDNSFile, "output-dns-file", "-", "DNS Output File (default - stdout)")
	flag.StringVar(&ControlDNSFile, "control-dns-file", "", "DNS Control File with trusted domain,ip,asn values to include when a domain has no IPs (default - \"\")")
	flag.StringVar(&DNSParsedOutput, "output-parsed-dns", "dns_parsed_output.csv", "DNS Parsed output file (default - dns_parsed_output.csv")
	flag.StringVar(&OutputConnFile, "output-conn-file", "-", "Output File for writing TCP, TLS and HTTP connection responses (default - stdout)")
	flag.StringVar(&OutputFailedConnFile, "output-failed-conn-file", "failed_conn.csv", "Output File for writing domain,ip pairs with failed tcp/tls connections, used to run traceroutes (default - failed_conn.csv)")
	flag.StringVar(&Module, "module", "full", "Module to run (can be dns, tcp or full (DNS + TCP) (default - full)")
	flag.IntVar(&NumWorkers, "num-workers", 100, "Number of vantage points to perform measurements to at any moment (default - 100)")
	flag.IntVar(&NumQueryWorkers, "num-query-workers", 3, "Number of qeuries to perform to each resolver at any moment (default - 3)")
	flag.IntVar(&NumRedirects, "num-redirects", 10, "Number of redirects to follow for an HTTP request (default 10)")
	flag.StringVar(&Srcip, "src-ip", "", "Source IP address to use (will use default if unspecified)")
	flag.BoolVar(&IgnoreLocalResolvers, "ignore-local-resolvers", false, "Does not add local resolvers in measurements when enabled (default - false)")
	flag.Parse()
}
