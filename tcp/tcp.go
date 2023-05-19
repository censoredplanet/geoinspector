package tcp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/censoredplanet/geoinspector/config"
	"github.com/censoredplanet/geoinspector/util"
	"github.com/miekg/dns"
	geoip2 "github.com/oschwald/geoip2-golang"
	zgrab2_http "github.com/zmap/zgrab2/lib/http"
)

type InputServer struct {
	Domain  string
	Ip      string
	Country string
}

/*
type SingleResponse struct {
	ConnectionContent interface{}
	Error             string
	Stage             int
}

*/

type Response struct {
	Endpoint  InputServer
	Responses []HTTPSData
}

type HTTPSData struct {
	StartTime           string
	EndTime             string
	IsDomainIncluded    bool
	Error               string
	Version             uint16
	HandshakeComplete   bool
	CipherSuite         uint16
	PeerCertificates    []byte
	HTTPResponseHeaders *zgrab2_http.Response
	HTTPResponseBody    string
	Redirects           []string
	RetryErrors         []string
}

func AppendSendResults(response Response, httpsData HTTPSData, results chan<- *Response) {
	httpsData.EndTime = time.Now().Round(0).String()
	response.Responses = append(response.Responses, httpsData)
	results <- &response
}

func extractTLSData(httpsDataObject *HTTPSData, state tls.ConnectionState) *HTTPSData {
	httpsDataObject.Version = state.Version
	httpsDataObject.HandshakeComplete = state.HandshakeComplete
	httpsDataObject.CipherSuite = state.CipherSuite
	httpsDataObject.PeerCertificates = state.PeerCertificates[0].Raw
	return httpsDataObject
}

func ParseHTTPResponse(http string) (*zgrab2_http.Response, error) {
	return zgrab2_http.ReadResponse(bufio.NewReader(strings.NewReader(http)), nil)
}

// SendHTTPRequest sends a HTTP GET for the path with Host set to domain.
func SendHTTPRequest(conn *tls.Conn, domain string, path string, httpsDataObject *HTTPSData) *HTTPSData {
	var request string
	if domain == "" {
		request = fmt.Sprintf("GET %s HTTP/1.1\r\nConnection: close\r\n\r\n", path)
	} else {
		request = fmt.Sprintf("GET %s HTTP/1.1\r\nHost:%s\r\nConnection: close\r\n\r\n", path, domain)
	}
	_, err := conn.Write([]byte(request))
	if err != nil {
		httpsDataObject.Error = "HTTP Write Error: " + err.Error()
		return httpsDataObject
	}
	maxResponseLength := 1 << 16
	httpResponse := make([]byte, maxResponseLength)
	http := ""

	responseLength := 0
	for {
		// TODO(adrs): add to config
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := conn.Read(httpResponse[responseLength:maxResponseLength])
		if err == io.EOF {
			break
		} else if err != nil {
			httpsDataObject.Error = "HTTP Read Error: " + err.Error()
			return httpsDataObject
		}
		responseLength += n
		if responseLength == maxResponseLength {
			http = http + string(httpResponse)
			httpResponse = make([]byte, maxResponseLength)
			responseLength = 0
		}
	}

	http = http + string(httpResponse)
	httpData, err := ParseHTTPResponse(http)
	if err != nil && err != io.EOF {
		httpsDataObject.Error = "HTTP Parse Error: " + err.Error()
		return httpsDataObject
	}
	httpsDataObject.HTTPResponseHeaders = httpData

	var body *bytes.Buffer
	body = new(bytes.Buffer)
	_, err = io.Copy(body, httpData.Body)
	httpsDataObject.HTTPResponseBody = body.String()
	return httpsDataObject
}

// needRedirect returns true if the response indicates a redirect to a valid Location.
func needRedirect(resp *HTTPSData) bool {
	switch status := resp.HTTPResponseHeaders.StatusCode; status {
	case 301, 302, 303, 307, 308:
		if _, err := resp.HTTPResponseHeaders.Location(); err != nil {
			return false
		}
		return true
	}
	return false
}

// dnsQueryA queries the resolver for the domain and returns the first A record.
func dnsQueryA(client dns.Client, resolver, domain string) (string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	dnsResp, _, err := client.Exchange(msg, resolver+":53")
	if err != nil {
		return "", err
	}
	if dnsResp.MsgHdr.Rcode != 0 {
		return "", fmt.Errorf(dns.RcodeToString[dnsResp.MsgHdr.Rcode])
	}
	// Return the first A record
	for _, rr := range dnsResp.Answer {
		switch rr.(type) {
		case *dns.A:
			return rr.(*dns.A).A.String(), nil
		}
	}
	return "", fmt.Errorf("No A records")
}

// SendHTTPRequestWithRedirects initiates a TLS connection to the host with the SNI field set to domain.
// Then if successful, sends a HTTP GET request with Host header as domain, following up to numRedirects.
// Redirects determines the redirect host, domain, and path from the previously returned location and
// initiates a new TLS connection to the redirect host with the SNI field set to the redirect domain,
// then sends a HTTP GET request for the redirect path with Host header as the redirect domain.
// Returns the parsed data from the TLS connection and HTTP request.
func SendHTTPRequestWithRedirects(host string, domain string, numRedirects int) *HTTPSData {
	var client dns.Client
	resp, conn, err := InitConn(host, domain)
	startTime := resp.StartTime
	redirects := []string{}
	if err == nil {
		resp = SendHTTPRequest(conn, domain, "/", resp)
		conn.Close()
	}
	redirectHost := host
	redirectDomain := domain
	for resp.Error == "" && needRedirect(resp) && numRedirects > 0 {
		// Redirect - get the Location from the response headers.
		numRedirects = numRedirects - 1
		location, _ := resp.HTTPResponseHeaders.Location()
		redirects = append(redirects, location.String())
		// If redirecting to new domain, lookup the IP.
		if location.Hostname() != "" && location.Hostname() != redirectDomain {
			redirectDomain = location.Hostname()
			redirectIp, err := dnsQueryA(client, "1.1.1.1", redirectDomain)
			if err != nil {
				resp.Error = "Redirect DNS Error: " + err.Error()
				break
			}
			redirectHost = redirectIp + ":443"
		}
		resp, conn, err = InitConn(redirectHost, redirectDomain)
		resp.StartTime = startTime
		if err == nil {
			resp = SendHTTPRequest(conn, redirectDomain, location.RequestURI(), resp)
			conn.Close()
		}
	}
	resp.Redirects = redirects
	resp.EndTime = time.Now().Round(0).String()
	return resp
}

// InitConn initiates a TLS connection to the host with the SNI field set to domain.
// Returns the parsed data from the TLS connection and the (open) connection object.
func InitConn(host string, domain string) (*HTTPSData, *tls.Conn, error) {
	var conn *tls.Conn
	var err error
	var data *HTTPSData
	var dialer *net.Dialer
	if config.Srcip != "" {
		dialer = &net.Dialer{
			LocalAddr: &net.TCPAddr{
				IP:   net.ParseIP(config.Srcip),
				Port: 0,
			},
			Timeout: 3 * time.Second,
		}
	} else {
		dialer = &net.Dialer{
			Timeout: 3 * time.Second,
		}
	}

	if domain == "" {
		data = &HTTPSData{
			IsDomainIncluded: false,
			StartTime:        time.Now().Round(0).String(),
			Redirects:        []string{},
		}
		conf := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", host, conf)
	} else {
		data = &HTTPSData{
			IsDomainIncluded: true,
			StartTime:        time.Now().Round(0).String(),
			Redirects:        []string{},
		}
		conf := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         domain,
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", host, conf)
	}
	if err != nil {
		data.Error = "TLS Error: " + err.Error()
	} else {
		state := conn.ConnectionState()
		data = extractTLSData(data, state)
	}
	return data, conn, err
}

func RequestWorker(jobs <-chan InputServer, results chan<- *Response, numRedirects int) {
	for job := range jobs {
		response := &Response{
			Endpoint: job,
		}

		host := fmt.Sprintf("%s:%s", job.Ip, "443")

		//First request - Send without SNI - IF TLS error, means the whole platform (not the specific domain) is geoblocking incoming TLS connections based on IP.
		//Send HTTP GET without Host - IF HTTP error, means the whole platform (not the specific domain) is geoblocking incoming HTTP connections based on IP.
		respNoSNI := SendHTTPRequestWithRedirects(host, "", numRedirects)
		response.Responses = append(response.Responses, *respNoSNI)

		//Second request - Send with SNI
		//Send request with HTTP host header set to the desired domain, asking for the home page
		var respSNI *HTTPSData
		retryErrors := []string{}
		for i := 0; i < 3; i++ {
			respSNI = SendHTTPRequestWithRedirects(host, job.Domain, numRedirects)
			if respSNI.Error == "" {
				break
			}
			retryErrors = append(retryErrors, respSNI.Error)
			respSNI.RetryErrors = retryErrors
			time.Sleep(time.Duration(config.MeasurementSeparation) * time.Second)
		}
		response.Responses = append(response.Responses, *respSNI)

		results <- response
	}
}

func asnLookup(asnMmdb *geoip2.Reader, ip string) string {
	if asnMmdb == nil {
		return "ASN"
	}
	address := net.ParseIP(ip)
	if address == nil {
		return "ASN"
	}
	data, err := asnMmdb.ASN(address)
	if err != nil {
		return "ASN"
	}
	return fmt.Sprintf("%v", data.AutonomousSystemNumber)
}

func ConnSendRecv(InputServers []*InputServer, port uint, numRedirects int) {
	log.Println("[TCP.ConnSendRecv] Creating conn output file")
	outputFile := util.CreateFile(config.OutputConnFile)
	outputFailedFile := util.CreateFile(config.OutputFailedConnFile)

	log.Println("[TCP.ConnSendRecv] Assinging jobs to connect to IP address")

	results := make(chan *Response, len(InputServers))
	jobs := make(chan InputServer, len(InputServers))
	for i := 0; i < config.NumWorkers; i++ {
		go RequestWorker(jobs, results, numRedirects)
	}
	for _, inputServer := range InputServers {
		jobs <- *inputServer
	}
	close(jobs)

	asnMmdb, err := geoip2.Open(config.AsnMmdb)
	if err != nil {
		asnMmdb = nil
	}

	failed := make(map[string]struct{})
	for i := 1; i <= len(InputServers); i++ {
		result := <-results
		util.SaveResults(result, outputFile)
		key := fmt.Sprintf("%s,%s,", result.Endpoint.Ip, result.Endpoint.Domain)
		// If the handshake is not completed and this is a new domain+ip, save.
		if _, ok := failed[key]; !ok {
			for i := 0; i < len(result.Responses); i++ {
				resp := result.Responses[i]
				// Check resp from grab with SNI.
				if resp.IsDomainIncluded && !resp.HandshakeComplete {
					asn := asnLookup(asnMmdb, result.Endpoint.Ip)
					outputFailedFile.WriteString(key + asn + "\n")
					failed[key] = struct{}{}
					break
				}
			}
		}
	}
}
