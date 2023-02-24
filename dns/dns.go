package dns

import (
	"bufio"
	"log"
	"os"
	"strings"
	"time"

	"github.com/censoredplanet/geoinspector/config"
	"github.com/censoredplanet/geoinspector/util"
	"github.com/miekg/dns"
)

// Data format for parsed DNS response
type ResponseResult struct {
	Response []ResponseEntry `json:"response"`
	Err      string          `json:"error"`
	Rcode    int             `json:"rcode"`
}

type ResponseEntry struct {
	Data string `json:"data"`
	Type string `json:"type"`
}

type QueryResponse struct {
	ResolverIP      string           `json:"resolver"`
	Domain          string           `json:"domain"`
	StartTime       string           `json:"start_time"`
	EndTime         string           `json:"end_time"`
	Responses       []ResponseResult `json:"responses"`
	TraceResults    []*TraceResult   `json:"trace"`
	AuthoritativeNs string           `json:"authoritative_ns"`
	Error           string           `json:"error"`
}

type InputDNSResolver struct {
	IP         string           `json:"ip"`
	Name       string           `json:"name"`
	Country    string           `json:"country"`
	Kind       string           `json:"kind"`
	WhoamiResp []ResponseResult `json:"whoami_resp"`
}

func addLocalDNSResolver(inputDNSResolvers []*InputDNSResolver) []*InputDNSResolver {
	resolvFile, err := os.Open("/etc/resolv.conf")
	if err != nil {
		log.Fatal("[DNS.addLocalDNSResolver] Error in opening /etc/resolv.conf: ", resolvFile)
	}
	scanner := bufio.NewScanner(resolvFile)
	var ips []string
	var name string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, " ")
		if len(parts) < 2 {
			continue
		}
		kind := parts[0]
		rest := parts[1:]

		switch kind {
		case "nameserver":
			n := strings.Join(rest, "")
			n = strings.TrimSpace(n)
			ips = append(ips, n)
		case "search":
			for _, s := range rest {
				s := strings.TrimSpace(s)
				if s != "" {
					name = s
				}
			}
		default:
			continue
		}
	}

	if len(ips) == 0 {
		log.Fatal("[DNS.addLocalDNSResolver] Could not find local DNS IP address from /etc/resolv.conf")
	}

	for _, ip := range ips {
		inputDNSResolvers = append(inputDNSResolvers, &InputDNSResolver{
			IP:      ip,
			Name:    name,
			Country: "TODO",
			Kind:    "Local",
		})
	}

	return inputDNSResolvers
}

// Parse DNS responses, return a list of {IP, err, Rcode, status} tuples
// And a bool variable to indicate whether there's a legit response from all the replies
func ParseDNS(resp *dns.Msg, err error, domain string) *ResponseResult {
	// Return parsed DNS and status
	parsed := &ResponseResult{
		Response: []ResponseEntry{},
		Err:      "null",
		Rcode:    -1,
	}

	// If there's an error, just return the error
	if err != nil || resp == nil {
		parsed.Err = err.Error()
		return parsed
	}

	// If answer field of DNS response is nil:
	// rcode should not be 0
	if resp.Answer != nil {
		parsed.Rcode = resp.Rcode
	} else {
		parsed.Err = "Server empty answer"
		return parsed
	}

	// Aggregate responses
	for _, rr := range resp.Answer {
		switch rr.(type) {
		case *dns.A:
			// If there's an A record, record the IP
			parsed.Response = append(parsed.Response, ResponseEntry{rr.(*dns.A).A.String(), "A"})
		case *dns.AAAA:
			parsed.Response = append(parsed.Response, ResponseEntry{rr.(*dns.AAAA).AAAA.String(), "AAAA"})
		case *dns.TXT:
			parsed.Response = append(parsed.Response, ResponseEntry{strings.Join(rr.(*dns.TXT).Txt, ";"), "TXT"})
		}
	}

	return parsed
}

// Worker to send DNS queries to target IP
func QueryWorker(client *dns.Client, resolver InputDNSResolver, domains <-chan string, results chan<- *QueryResponse) {
	// Loop jobs channel until it is closed
	for testDomain := range domains {
		// Initialize default value assignment
		reply := &QueryResponse{
			ResolverIP: resolver.IP,
			Domain:     testDomain,
			Responses:  make([]ResponseResult, 0),
			Error:      "",
		}
		// Iteratively get authoritative nameserver
		reply.StartTime = time.Now().Round(0).String()

		//If recurive, perform trace, else perform normal query
		if resolver.IP == "recursive" {
			reply.TraceResults, reply.AuthoritativeNs = recursiveTrace(testDomain)
			if reply.AuthoritativeNs != "" {
				// Start trials for test domain
				msg := new(dns.Msg)
				msg.SetQuestion(dns.Fqdn(testDomain), dns.TypeA)
				// Trial 3 times
				for i := 0; i < 3; i++ {
					resp, _, err := client.Exchange(msg, reply.AuthoritativeNs+":53")
					parsed := ParseDNS(resp, err, testDomain)
					reply.Responses = append(reply.Responses, *parsed)
					reply.Error = parsed.Err
					if parsed.Err == "null" {
						break
					}
					time.Sleep(1 * time.Second)
				}
			} else {
				reply.Error = "Iterative error"
			}
		} else {
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(testDomain), dns.TypeA)
			// Trial 3 times
			for i := 0; i < 3; i++ {
				resp, _, err := client.Exchange(msg, resolver.IP+":53")
				parsed := ParseDNS(resp, err, testDomain)
				reply.Responses = append(reply.Responses, *parsed)
				reply.Error = parsed.Err
				if parsed.Err == "null" {
					break
				}
				time.Sleep(1 * time.Second)
			}
		}
		reply.EndTime = time.Now().Round(0).String()
		results <- reply
	}
}

// Worker per resolver
func ResolverWorker(inputURLs []*util.InputURL, resolvers <-chan InputDNSResolver, done chan<- *QueryResponse) {
	for resolver := range resolvers {
		// Spawn query workers for this resolver
		client := new(dns.Client)
		results := make(chan *QueryResponse, len(inputURLs))
		jobs := make(chan string, len(inputURLs))
		for i := 0; i < config.NumQueryWorkers; i++ {
			go QueryWorker(client, resolver, jobs, results)
		}
		// Send jobs, which are domains to query for, randomly
		// Randomness needed so no one website is strained
		for _, inputURL := range inputURLs {
			jobs <- inputURL.Domain
		}
		close(jobs)
		// Send results to the main goroutine
		for i := 0; i < len(inputURLs); i++ {
			result := <-results
			done <- result
		}
	}
}

type TraceEntry struct {
	Data string   `json:"data"`
	Glue []string `json:"glue"`
}

type TraceResult struct {
	Ns       string       `json:"ns"`
	Domain   string       `json:"domain"`
	Response []TraceEntry `json:"responses"`
	Err      string       `json:"error"`
	Rcode    int          `json:"rcode"`
}

// Modified from https://gist.github.com/andrewtj/056ed6225898d652288f0d416eb3cc3f
func recursiveTrace(targetDomain string) ([]*TraceResult, string) {
	var client dns.Client
	q := new(dns.Msg).SetQuestion(dns.Fqdn(targetDomain), dns.TypeNS)
	q.MsgHdr.RecursionDesired = false

	var traceResults []*TraceResult
	traceResults = append(traceResults, &TraceResult{
		Domain: ".",
		// F-Root is operated by Cloudflare :-)
		Response: []TraceEntry{{Data: "f.root-servers.net.", Glue: []string{"192.5.5.241"}}},
	})

	traceTerminated := false
	authoritativeFound := false
	authoritativeNs := ""
	var r *dns.Msg
	var target string
	var err error
	for !authoritativeFound && !traceTerminated {
		q.Id = dns.Id()
		nameServers := traceResults[len(traceResults)-1].Response
		for nsI := 0; nsI < len(nameServers); nsI++ {
			// Get next resolver
			target = nameServers[nsI].Data
			if len(nameServers[nsI].Glue) > 0 { // If glue record is provided, use glued IP
				target = nameServers[nsI].Glue[0]
			}
			// Try to query up to three times
			for i := 0; i < 3; i++ {
				r, _, err = client.Exchange(q, target+":53")
				if err == nil {
					break
				}
			}
			if err == nil {
				break
			}
		}

		result := &TraceResult{
			Ns:       target,
			Domain:   targetDomain,
			Response: []TraceEntry{},
			Err:      "null",
			Rcode:    -1,
		}

		if err != nil || r == nil {
			result.Err = err.Error()
			traceResults = append(traceResults, result)
			break
		}

		result.Rcode = r.MsgHdr.Rcode
		switch {
		case r.MsgHdr.Rcode != dns.RcodeSuccess:
			result.Err = dns.RcodeToString[r.MsgHdr.Rcode]
			traceTerminated = true
		case r.MsgHdr.Authoritative:
			authoritativeNs = target
			authoritativeFound = true
		case len(r.Ns) == 0:
			result.Err = "No NS server presented in response"
			traceTerminated = true
		default:
			result.Domain = r.Ns[0].Header().Name

			// Process glue records
			glueRecords := make(map[string][]string)
			for _, rrInterface := range r.Extra {
				if rr, ok := rrInterface.(*dns.A); ok {
					glueRecords[rr.Hdr.Name] = append(glueRecords[rr.Hdr.Name], rr.A.String())
				}
			}

			for _, ns := range r.Ns {
				if ns, ok := ns.(*dns.NS); ok {
					result.Response = append(result.Response, TraceEntry{Data: ns.Ns, Glue: glueRecords[ns.Ns]})
				}
			}
		}

		if !authoritativeFound {
			traceResults = append(traceResults, result)
		}
	}

	return traceResults[1:], authoritativeNs // Ignore the root server
}

func whoamiResolver(resolver *InputDNSResolver) {
	for _, whoamiEndpoint := range config.WhoamiEndpoints {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(whoamiEndpoint), dns.TypeTXT)
		client := new(dns.Client)

		for i := 0; i < 3; i++ {
			resp, _, err := client.Exchange(msg, resolver.IP+":53")
			parsed := ParseDNS(resp, err, whoamiEndpoint)
			resolver.WhoamiResp = append(resolver.WhoamiResp, *parsed)
			// Only conduct the second liveness test if connection error
			if parsed.Err == "null" {
				break
			}
		}
	}
}

func DNS(inputDNSResolvers []*InputDNSResolver, inputURLs []*util.InputURL) {
	log.Println("[DNS.dns] Creating DNS output file")
	outputFile := util.CreateFile(config.OutputDNSFile)
	outputMetaFile := util.CreateFile(config.OutputDNSFile + "-metainfo")

	if !config.IgnoreLocalResolvers {
		log.Println("[DNS.dns] Adding Local DNS resolver to list")
		inputDNSResolvers = addLocalDNSResolver(inputDNSResolvers)
	}

	log.Println("[DNS.dns] Querying whoami endpoints for all resolvers")
	for _, resolver := range inputDNSResolvers {
		whoamiResolver(resolver)
		util.SaveResults(resolver, outputMetaFile)
	}

	log.Println("[DNS.dns] Assinging DNS query jobs")

	results := make(chan *QueryResponse, len(inputDNSResolvers))
	jobs := make(chan InputDNSResolver, len(inputDNSResolvers))
	for i := 0; i < config.NumWorkers; i++ {
		go ResolverWorker(inputURLs, jobs, results)
	}
	for _, inputDNSResolver := range inputDNSResolvers {
		jobs <- *inputDNSResolver
	}
	close(jobs)

	for i := 1; i <= len(inputDNSResolvers)*len(inputURLs); i++ {
		result := <-results
		util.SaveResults(result, outputFile)
	}

	log.Println("[DNS.dns] Performing recursive DNS traces")
	//Perform recursive trace queries
	client := new(dns.Client)
	recursiveJobs := make(chan string, len(inputURLs))
	recursiveResolver := &InputDNSResolver{
		IP:      "recursive",
		Name:    "recursive",
		Country: "TODO",
		Kind:    "recursive",
	}
	for i := 0; i < config.NumWorkers; i++ {
		go QueryWorker(client, *recursiveResolver, recursiveJobs, results)
	}
	// Send jobs, which are domains to query for, randomly
	// Randomness needed so no one website is strained
	for _, inputURL := range inputURLs {
		recursiveJobs <- inputURL.Domain
	}
	close(recursiveJobs)
	// Send results to the main goroutine
	for i := 0; i < len(inputURLs); i++ {
		result := <-results
		util.SaveResults(result, outputFile)
	}
}
