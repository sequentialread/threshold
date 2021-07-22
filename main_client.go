package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	errors "git.sequentialread.com/forest/pkg-errors"
	tunnel "git.sequentialread.com/forest/threshold/tunnel-lib"
	"git.sequentialread.com/forest/threshold/tunnel-lib/proto"
	proxyprotocol "github.com/armon/go-proxyproto"
	"golang.org/x/net/proxy"
)

type ClientConfig struct {
	DebugLog                bool
	ClientId                string
	GreenhouseDomain        string
	GreenhouseAPIToken      string
	GreenhouseThresholdPort int

	// Theshold client will listen for SOCKS5 connections on the specified port (for example, "127.0.0.1:1080")
	// and tunnel them to the threshold server, where the server will handle the SOCKS5 CONNECT requests
	// and proxy the connections. Use this for hosting email servers or any other server where Outbound
	// connections have to come from the same IP address which is used for Inbound connections
	TunneledOutboundSOCKS5ListenAddress string

	MaximumConnectionRetrySeconds int
	ServerAddr                    string
	Servers                       []string
	DefaultTunnels                *LiveConfigUpdate
	CaCertificateFilesGlob        string
	ClientTlsKeyFile              string
	ClientTlsCertificateFile      string
	CaCertificate                 string
	ClientTlsKey                  string
	ClientTlsCertificate          string

	// Use this when a local proxy is required for threshold client (this app) to talk to the threshold server.
	// For example, if a firewall or other hostile network environment might otherwise prevent you from connecting.
	// This would be the address of an external 3rd party SOCKS5 proxy server that is reachable from your computer.
	// If you set the hostname to "gateway", like "HostileNetworkEnvironmentEvasionSOCKS5Address": "gateway:1080"
	// then it will try to SOCKS5 connect to any/all default gateways (routers) on the given port (1080 in this case).
	HostileNetworkEnvironmentEvasionSOCKS5Address string

	AdminUnixSocket            string
	AdminAPIPort               int
	AdminAPICACertificateFile  string
	AdminAPITlsKeyFile         string
	AdminAPITlsCertificateFile string
	Metrics                    MetricsConfig
}

type ClientServer struct {
	Client         *tunnel.Client
	ServerUrl      *url.URL
	ServerHostPort string
}

type LiveConfigUpdate struct {
	Listeners             []ListenerConfig
	ServiceToLocalAddrMap map[string]string
}

type ThresholdTenantInfo struct {
	ThresholdServers []string
}

type maximumBackoff struct {
	Maximum time.Duration
	Base    tunnel.Backoff
}

func (bo *maximumBackoff) NextBackOff() time.Duration {
	result := bo.Base.NextBackOff()
	if result > bo.Maximum {
		return bo.Maximum
	}
	return result
}

func (bo *maximumBackoff) Reset() {
	bo.Base.Reset()
}

type clientAdminAPI struct{}

// Client State
var clientServers []ClientServer
var tlsClientConfig *tls.Config
var serviceToLocalAddrMap *map[string]string

var isTestMode bool
var testModeListeners map[string]ListenerConfig
var testModeTLSConfig *tls.Config
var testTokens []string

func runClient(configFileName *string) {

	configBytes := getConfigBytes(configFileName)

	var config ClientConfig
	err := json.Unmarshal(configBytes, &config)
	if err != nil {
		log.Fatalf("runClient(): can't json.Unmarshal(configBytes, &config) because %s \n", err)
	}

	if config.GreenhouseThresholdPort == 0 {
		config.GreenhouseThresholdPort = 9056
	}
	if config.TunneledOutboundSOCKS5ListenAddress == "" {
		config.TunneledOutboundSOCKS5ListenAddress = "127.0.0.1:1080"
	}
	tunneledOutboundSOCKS5ListenAddress, err := net.ResolveTCPAddr("tcp", config.TunneledOutboundSOCKS5ListenAddress)
	if err != nil {
		log.Fatalf("runClient(): can't net.ResolveTCPAddr(TunneledOutboundSOCKS5ListenAddress) because %s \n", err)
	}
	forwardProxyListener, err := net.ListenTCP("tcp", tunneledOutboundSOCKS5ListenAddress)
	if err != nil {
		log.Fatalf("runClient(): can't net.ListenTCP(\"tcp\", TunneledOutboundSOCKS5ListenAddress) because %s \n", err)
	}

	clientServers = []ClientServer{}
	makeServer := func(hostPort string) ClientServer {
		serverURLString := fmt.Sprintf("https://%s", hostPort)
		serverURL, err := url.Parse(serverURLString)
		if err != nil {
			log.Fatal(fmt.Errorf("failed to parse the ServerAddr (prefixed with https://) '%s' as a url", serverURLString))
		}
		return ClientServer{
			ServerHostPort: hostPort,
			ServerUrl:      serverURL,
		}
	}

	serverListToLog := ""

	if config.GreenhouseDomain != "" {
		if config.ServerAddr != "" {
			log.Fatal("config contains both GreenhouseDomain and ServerAddr, only use one or the other")
		}
		if config.Servers != nil && len(config.Servers) > 0 {
			log.Fatal("config contains both GreenhouseDomain and Servers, only use one or the other")
		}
		if config.GreenhouseAPIToken == "" {
			log.Fatal("config contains GreenhouseDomain but does not contain GreenhouseAPIToken, use both or niether")
		}

		greenhouseClient := http.Client{Timeout: time.Second * 10}
		greenhouseURL := fmt.Sprintf("https://%s/api/tenant_info", config.GreenhouseDomain)
		request, err := http.NewRequest("GET", greenhouseURL, nil)
		if err != nil {
			log.Fatal("invalid GreenhouseDomain '%s', can't create http request for %s", config.GreenhouseDomain, greenhouseURL)
		}
		request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", config.GreenhouseAPIToken))

		hostPortStringsToLog := []string{}
		response, err := greenhouseClient.Do(request)
		if err != nil || response.StatusCode != 200 {
			if err == nil {
				if response.StatusCode == 401 {
					log.Fatalf("bad or expired GreenhouseAPIToken, recieved HTTP 401 Unauthorized from Greenhouse server %s", greenhouseURL)
				} else {
					log.Fatalf("server error: recieved HTTP %d from Greenhouse server %s", response.StatusCode, greenhouseURL)
				}
			}
			log.Printf("can't reach %s, falling back to DNS lookup...\n", greenhouseURL)
			ips, err := net.LookupIP(config.GreenhouseDomain)
			if err != nil {
				log.Fatalf("Failed to lookup GreenhouseDomain '%s'", config.GreenhouseDomain)
			}
			for _, ip := range ips {
				serverHostPort := fmt.Sprintf("%s:%d", ip, config.GreenhouseThresholdPort)
				clientServers = append(clientServers, makeServer(serverHostPort))
				hostPortStringsToLog = append(hostPortStringsToLog, serverHostPort)
			}
		} else {
			responseBytes, err := ioutil.ReadAll(response.Body)
			if err != nil {
				log.Fatal("http read error GET '%s'", greenhouseURL)
			}
			var tenantInfo ThresholdTenantInfo
			err = json.Unmarshal(responseBytes, &tenantInfo)
			if err != nil {
				log.Fatal("http read error GET '%s'", greenhouseURL)
			}

			for _, serverHostPort := range tenantInfo.ThresholdServers {
				clientServers = append(clientServers, makeServer(serverHostPort))
				hostPortStringsToLog = append(hostPortStringsToLog, serverHostPort)
			}
		}

		serverListToLog = fmt.Sprintf("%s (%s)", config.GreenhouseDomain, strings.Join(hostPortStringsToLog, ", "))

	} else if config.Servers != nil && len(config.Servers) > 0 {
		if config.ServerAddr != "" {
			log.Fatal("config contains both Servers and ServerAddr, only use one or the other")
		}
		for _, serverHostPort := range config.Servers {
			clientServers = append(clientServers, makeServer(serverHostPort))
		}
		serverListToLog = fmt.Sprintf("[%s]", strings.Join(config.Servers, ", "))
	} else {
		clientServers = []ClientServer{makeServer(config.ServerAddr)}
		serverListToLog = config.ServerAddr
	}

	if config.DefaultTunnels != nil {
		serviceToLocalAddrMap = &config.DefaultTunnels.ServiceToLocalAddrMap
	} else {
		serviceToLocalAddrMap = &(map[string]string{})
	}

	configToLog, _ := json.MarshalIndent(config, "", "  ")
	configToLogString := string(configToLog)

	configToLogString = regexp.MustCompile(
		`("GreenhouseAPIToken": ")[^"]+(",)`,
	).ReplaceAllString(
		configToLogString,
		"$1******$2",
	)
	configToLogString = regexp.MustCompile(
		`("(CaCertificate|ClientTlsKey|ClientTlsCertificate)": "[^"]{27})[^"]+([^"]{27}")`,
	).ReplaceAllString(
		configToLogString,
		"$1 blahblahPEMblahblah $3",
	)

	log.Printf("theshold client is starting up using config:\n%s\n", configToLogString)

	var proxyDialer proxy.Dialer = nil
	dialFunction := net.Dial

	if config.HostileNetworkEnvironmentEvasionSOCKS5Address != "" {
		proxyDialer, err = getProxyDialer(config.HostileNetworkEnvironmentEvasionSOCKS5Address)
		if err != nil {
			log.Fatalf("can't start because can't getProxyDialer(): %+v", err)
		}
		dialFunction = func(network, address string) (net.Conn, error) {
			var err error
			if proxyDialer == nil {
				proxyDialer, err = getProxyDialer(config.HostileNetworkEnvironmentEvasionSOCKS5Address)
				if err != nil {
					return nil, errors.Wrap(err, "dialFunction failed to recreate proxyDialer: ")
				}
			}

			// if it fails, set it to null so it will be re-created // TODO test this and verify it actually works 0__0
			conn, err := proxyDialer.Dial(network, address)
			if err != nil {
				proxyDialer = nil
			}
			return conn, err
		}
	}

	var cert tls.Certificate
	hasFiles := config.ClientTlsCertificateFile != "" && config.ClientTlsKeyFile != ""
	hasLiterals := config.ClientTlsCertificate != "" && config.ClientTlsKey != ""
	if hasFiles && !hasLiterals {
		cert, err = tls.LoadX509KeyPair(config.ClientTlsCertificateFile, config.ClientTlsKeyFile)
		if err != nil {
			log.Fatalf("can't start because tls.LoadX509KeyPair returned: \n%+v\n", err)
		}
	} else if !hasFiles && hasLiterals {
		cert, err = tls.X509KeyPair([]byte(config.ClientTlsCertificate), []byte(config.ClientTlsKey))
		if err != nil {
			log.Fatalf("can't start because tls.X509KeyPair returned: \n%+v\n", err)
		}

	} else {
		log.Fatal("one or the other (not both) of ClientTlsCertificateFile+ClientTlsKeyFile or ClientTlsCertificate+ClientTlsKey is required\n")
	}

	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	if parsedCert == nil {
		log.Fatalf("parsedCert is nil (%s)", config.ClientTlsCertificateFile)
	}
	commonName := parsedCert.Subject.CommonName
	clientIdDomain := strings.Split(commonName, "@")

	if len(clientIdDomain) != 2 {
		log.Fatal(fmt.Errorf(
			"expected TLS client certificate common name '%s' to match format '<clientId>@<domain>'", commonName,
		))
	}

	// This is enforced by the server anyways, so no need to enforce it here.
	// This allows server URLs to use IP addresses, don't require DNS.
	// if clientIdDomain[1] != serverURL.Hostname() {
	// 	log.Fatal(fmt.Errorf(
	// 		"expected TLS client certificate common name domain '%s' to match ServerAddr domain '%s'",
	// 		clientIdDomain[1], serverURL.Hostname(),
	// 	))
	// }

	if clientIdDomain[0] != config.ClientId {
		log.Fatal(fmt.Errorf(
			"expected TLS client certificate common name clientId '%s' to match ClientId '%s'",
			clientIdDomain[0], config.ClientId,
		))
	}

	caCertPool := x509.NewCertPool()
	if config.CaCertificateFilesGlob != "" && config.CaCertificate == "" {
		certificates, err := filepath.Glob(config.CaCertificateFilesGlob)
		if err != nil {
			log.Fatal(err)
		}

		for _, filename := range certificates {
			caCert, err := ioutil.ReadFile(filename)
			if err != nil {
				log.Fatal(err)
			}
			ok := caCertPool.AppendCertsFromPEM(caCert)
			if !ok {
				log.Fatalf("Failed to add CA certificate '%s' to cert pool\n", filename)
			}
		}
	} else if config.CaCertificateFilesGlob == "" && config.CaCertificate != "" {
		ok := caCertPool.AppendCertsFromPEM([]byte(config.CaCertificate))
		if !ok {
			log.Fatal("Failed to add config.CaCertificate to cert pool\n")
		}
	} else {
		log.Fatal("one or the other (not both) of CaCertificateFilesGlob or CaCertificate is required\n")
	}

	tlsClientConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsClientConfig.BuildNameToCertificate()

	// wrap whatever dial function we have right now with TLS.
	existingDialFunction := dialFunction
	dialFunction = func(network, address string) (net.Conn, error) {
		conn, err := existingDialFunction(network, address)
		if err != nil {
			return nil, err
		}

		addressSplit := strings.Split(address, ":")
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:   addressSplit[0],
			Certificates: tlsClientConfig.Certificates,
			RootCAs:      tlsClientConfig.RootCAs,
		})
		err = tlsConn.Handshake()
		if err != nil {
			return nil, err
		}
		return tlsConn, nil
	}

	go runClientAdminApi(config)

	fetchLocalAddr := func(service string) (string, error) {
		//log.Printf("(*serviceToLocalAddrMap): %+v\n\n", (*serviceToLocalAddrMap))
		localAddr, hasLocalAddr := (*serviceToLocalAddrMap)[service]
		if !hasLocalAddr {
			return "", fmt.Errorf("service '%s' not configured. Set ServiceToLocalAddrMap in client config file or HTTP PUT /liveconfig over the admin api.", service)
		}
		return localAddr, nil
	}

	productionProxyFunc := (&tunnel.TCPProxy{
		FetchLocalAddr: fetchLocalAddr,
		DebugLog:       config.DebugLog,
	}).Proxy

	proxyFunc := func(remote net.Conn, msg *proto.ControlMessage) {
		if isTestMode {
			handleTestConnection(remote, msg)
		} else {
			productionProxyFunc(remote, msg)
		}
	}

	maximumConnectionRetrySeconds := 60
	if config.MaximumConnectionRetrySeconds != 0 {
		maximumConnectionRetrySeconds = config.MaximumConnectionRetrySeconds
	}
	for i, server := range clientServers {
		// make a separate backoff instance for each server.
		myBackoff := maximumBackoff{
			Maximum: time.Second * time.Duration(maximumConnectionRetrySeconds),
			Base:    tunnel.NewExponentialBackoff(),
		}
		clientStateChanges := make(chan *tunnel.ClientStateChange)
		tunnelClientConfig := &tunnel.ClientConfig{
			DebugLog:       config.DebugLog,
			Identifier:     config.ClientId,
			ServerAddr:     server.ServerHostPort,
			FetchLocalAddr: fetchLocalAddr,
			Proxy:          proxyFunc,
			Dial:           dialFunction,
			StateChanges:   clientStateChanges,
			Backoff:        &myBackoff,
		}

		client, err := tunnel.NewClient(tunnelClientConfig)
		if err != nil {
			log.Fatalf("runClient(): can't create tunnel client for %s because %v \n", server.ServerHostPort, err)
		}

		go (func() {
			for {
				stateChange := <-clientStateChanges
				log.Printf("%s clientStateChange: %s\n", server.ServerHostPort, stateChange.String())
				if config.DefaultTunnels != nil && stateChange.Current == tunnel.ClientConnected {
					go (func() {
						failed := true
						for failed {
							err := updateListenersOnServer(config.DefaultTunnels.Listeners)
							if err != nil {
								log.Printf("DefaultTunnels: failed to updateListenersOnServer(): %+v\nRetrying in 5 seconds...\n", err)
								time.Sleep(time.Second * 5)
							} else {
								failed = false
							}
						}
					})()
				}
			}
		})()

		server.Client = client
		clientServers[i] = server
		go server.Client.Start()
	}

	log.Printf(
		"runClient(): the threshold client should be running now 🏔️⛰️🛤️⛰️🏔️ \n connecting to %s... \n",
		serverListToLog,
	)

	log.Printf(
		"runClient(): I am listening on %s for SOCKS5 forward proxy \n",
		config.TunneledOutboundSOCKS5ListenAddress,
	)

	for {
		conn, err := forwardProxyListener.Accept()
		if err != nil {
			log.Printf("Can't accept incoming connection: forwardProxyListener.Accept() returned %s\n", err)
		}

		// TODO better way of determining which one to use for forward proxy.
		// log.Printf("clientServers: %+v, clientServers[0]: %+v\n", clientServers, clientServers[0])
		err = clientServers[0].Client.HandleForwardProxy(conn)
		if err != nil {
			log.Printf("Can't accept incoming connection %s -> %s because %s\n", conn.RemoteAddr, conn.LocalAddr, err)
		}
	}

}

func runClientAdminApi(config ClientConfig) {

	var listener net.Listener
	if config.AdminUnixSocket != "" && config.AdminAPIPort == 0 {
		os.Remove(config.AdminUnixSocket)

		listenAddress, err := net.ResolveUnixAddr("unix", config.AdminUnixSocket)
		if err != nil {
			panic(fmt.Sprintf("runClient(): can't start because net.ResolveUnixAddr() returned %+v", err))
		}

		listener, err = net.ListenUnix("unix", listenAddress)
		if err != nil {
			panic(fmt.Sprintf("can't start because net.ListenUnix() returned %+v", err))
		}
		log.Printf("AdminUnixSocket Listening: %v\n\n", config.AdminUnixSocket)
		defer listener.Close()
	} else if config.AdminUnixSocket == "" && config.AdminAPIPort != 0 {
		addrString := fmt.Sprintf("127.0.0.1:%d", config.AdminAPIPort)
		addr, err := net.ResolveTCPAddr("tcp", addrString)
		if err != nil {
			panic(fmt.Sprintf("runClient(): can't start because net.ResolveTCPAddr(%s) returned %+v", addrString, err))
		}
		tcpListener, err := net.ListenTCP("tcp", addr)
		if err != nil {
			panic(fmt.Sprintf("runClient(): can't start because net.ListenTCP(%s) returned %+v", addrString, err))
		}

		caCertPool := x509.NewCertPool()
		caCertBytes, err := ioutil.ReadFile(config.AdminAPICACertificateFile)
		if err != nil {
			panic(fmt.Sprintf("runClient(): can't start because ioutil.ReadFile(%s) returned %+v", config.AdminAPICACertificateFile, err))
		}
		caCertPool.AppendCertsFromPEM(caCertBytes)

		tlsCert, err := tls.LoadX509KeyPair(config.AdminAPITlsCertificateFile, config.AdminAPITlsKeyFile)
		if err != nil {
			panic(fmt.Sprintf(
				"runClient(): can't start because tls.LoadX509KeyPair(%s,%s) returned %+v",
				config.AdminAPITlsCertificateFile, config.AdminAPITlsKeyFile, err,
			))
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			ClientCAs:    caCertPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		}
		tlsConfig.BuildNameToCertificate()

		listener = tls.NewListener(tcpListener, tlsConfig)
	} else if config.AdminUnixSocket != "" && config.AdminAPIPort != 0 {
		log.Fatal("One or the other (and not both) of AdminUnixSocket or AdminAPIPort is required")
		return
	} else if config.AdminUnixSocket == "" && config.AdminAPIPort == 0 {
		return
	}

	server := http.Server{
		Handler:      clientAdminAPI{},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	err := server.Serve(listener)
	if err != nil {
		panic(fmt.Sprintf("Admin API server returned %+v", err))
	}
}

// client admin api handler for /liveconfig over unix socket
func (handler clientAdminAPI) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	switch path.Clean(request.URL.Path) {
	case "/start_test":
		isTestMode = true
		testTokens = []string{}
		if testModeTLSConfig == nil {
			certificate, err := GenerateTestX509Cert()
			if err != nil {
				log.Printf("clientAdminAPI: GenerateTestX509Cert failed: %+v\n\n", err)
				http.Error(response, "500 GenerateTestX509Cert failed", http.StatusInternalServerError)
				return
			}
			testModeTLSConfig = &tls.Config{
				Certificates: []tls.Certificate{certificate},
			}
			testModeTLSConfig.BuildNameToCertificate()
		}
		response.Write([]byte("OK"))
	case "/end_test":
		isTestMode = false
		response.Header().Set("Content-Type", "text/plain")
		for _, testToken := range testTokens {
			response.Write([]byte(fmt.Sprintln(testToken)))
		}
	case "/liveconfig":
		if request.Method == "PUT" {
			requestBytes, err := ioutil.ReadAll(request.Body)
			if err != nil {
				log.Printf("clientAdminAPI: request read error: %+v\n\n", err)
				http.Error(response, "500 request read error", http.StatusInternalServerError)
				return
			}
			var configUpdate LiveConfigUpdate
			err = json.Unmarshal(requestBytes, &configUpdate)
			if err != nil {
				log.Printf("clientAdminAPI: can't parse JSON: %+v\n\n", err)
				http.Error(response, "400 bad request: can't parse JSON", http.StatusBadRequest)
				return
			}

			err = updateListenersOnServer(configUpdate.Listeners)
			if err != nil {
				log.Printf("clientAdminAPI: can't updateListenersOnServer(): %+v\n\n", err)
				http.Error(response, "500 internal server error", http.StatusInternalServerError)
				return
			}

			if &configUpdate.ServiceToLocalAddrMap != nil {
				serviceToLocalAddrMap = &configUpdate.ServiceToLocalAddrMap
			}

			response.Header().Add("content-type", "application/json")
			response.WriteHeader(http.StatusOK)
			response.Write(requestBytes)

		} else {
			response.Header().Set("Allow", "PUT")
			http.Error(response, "405 method not allowed, try PUT", http.StatusMethodNotAllowed)
		}
	default:
		http.Error(response, "404 not found, try PUT /liveconfig or PUT/GET /testmode", http.StatusNotFound)
	}

}

func updateListenersOnServer(listeners []ListenerConfig) error {
	sendBytes, err := json.Marshal(listeners)
	if err != nil {
		return errors.Wrap(err, "Listeners json serialization failed")
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsClientConfig,
		},
		Timeout: 10 * time.Second,
	}

	// TODO make this concurrent requests, not one by one.
	for _, server := range clientServers {
		apiURL := fmt.Sprintf("https://%s/tunnels", server.ServerHostPort)
		tunnelsRequest, err := http.NewRequest("PUT", apiURL, bytes.NewReader(sendBytes))
		if err != nil {
			return errors.Wrap(err, "error creating tunnels request")
		}
		tunnelsRequest.Header.Add("content-type", "application/json")

		tunnelsResponse, err := client.Do(tunnelsRequest)
		if err != nil {
			return errors.Wrap(err, "tunnels request failed")
		}
		tunnelsResponseBytes, err := ioutil.ReadAll(tunnelsResponse.Body)
		if err != nil {
			return errors.Wrap(err, "tunnels request response read error")
		}

		if tunnelsResponse.StatusCode != http.StatusOK {
			return errors.Errorf("tunnelsRequest returned HTTP %d: %s", tunnelsResponse.StatusCode, string(tunnelsResponseBytes))
		}
	}

	// cache the listeners locally for use in test mode.
	testModeListeners = map[string]ListenerConfig{}
	for _, listener := range listeners {
		testModeListeners[listener.BackEndService] = listener
	}

	return nil
}

func handleTestConnection(remote net.Conn, msg *proto.ControlMessage) {
	listenerInfo, hasListenerInfo := testModeListeners[msg.Service]
	log.Printf("handleTestConnection: %s (%s, %d)", msg.Service, listenerInfo.ListenHostnameGlob, listenerInfo.ListenPort)
	if !hasListenerInfo {
		remote.Close()
		return
	}
	if listenerInfo.HaProxyProxyProtocol {
		remote = proxyprotocol.NewConn(remote, time.Second*5)
	}
	if listenerInfo.ListenHostnameGlob != "" && listenerInfo.ListenHostnameGlob != "*" {
		// TODO make greenhouse-desktop always use HAPROXY proxy protocol with Caddy
		// so caddy can get the real remote IP
		if listenerInfo.ListenPort == 80 {
			requestBuffer := make([]byte, 1024)
			bytesRead, err := remote.Read(requestBuffer)
			if err != nil {
				remote.Close()
			} else {
				result := regexp.MustCompile("GET /([^ ]+) HTTP/1.1").FindStringSubmatch(string(requestBuffer[:bytesRead]))
				if result != nil && len(result) == 2 {
					testToken := result[1]
					testTokens = append(testTokens, testToken)
					remote.Write([]byte(fmt.Sprintf(`HTTP/1.1 200 OK
Content-Type: text/plain

%s`, testToken)))
					// TODO add remote.RemoteAddr().String()
					remote.Close()
				}
			}
		} else {
			remote_tls := tls.Server(remote, testModeTLSConfig)
			err := remote_tls.Handshake()
			if err != nil {
				remote_tls.Close()
				return
			}
			requestBuffer := make([]byte, 1024)
			bytesRead, err := remote_tls.Read(requestBuffer)
			if err != nil {
				remote_tls.Close()
				return
			}
			testToken := string(requestBuffer[:bytesRead])
			testTokens = append(testTokens, testToken)
			remote_tls.Write([]byte(testToken))
			remote_tls.Close()
		}
	} else {
		requestBuffer := make([]byte, 1024)
		bytesRead, err := remote.Read(requestBuffer)
		if err != nil {
			remote.Close()
			return
		}
		testToken := string(requestBuffer[:bytesRead])
		testTokens = append(testTokens, testToken)
		remote.Write([]byte(testToken))
		remote.Close()
	}
}

// https://gist.github.com/shivakar/cd52b5594d4912fbeb46
// create a bogus TLS key pair for the test server to use -- the test client will use InsecureSkipVerify
func GenerateTestX509Cert() (tls.Certificate, error) {
	now := time.Now()

	subjectKeyIDByteSlice := make([]byte, 10)
	rand.Read(subjectKeyIDByteSlice)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject: pkix.Name{
			CommonName:         "threshold-test-certificate.example.com",
			Country:            []string{"USA"},
			Organization:       []string{"example.com"},
			OrganizationalUnit: []string{"threshold-test-certificate"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(99, 0, 0), // Valid for long time (99 years)
		SubjectKeyId:          subjectKeyIDByteSlice,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template,
		priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	var outCert tls.Certificate
	outCert.Certificate = append(outCert.Certificate, cert)
	outCert.PrivateKey = priv

	return outCert, nil
}

func getProxyDialer(socks5Address string) (proxy.Dialer, error) {
	if strings.HasPrefix(strings.ToLower(socks5Address), "gateway") {
		splitAddress := strings.Split(socks5Address, ":")
		if len(splitAddress) != 2 {
			return nil, errors.Errorf("can't getProxyDialer() because HostileNetworkEnvironmentEvasionSOCKS5Address '%s' was invalid. should be of the form host:port")
		}
		port := splitAddress[1]
		defaultGateways, err := getDefaultGatewaysFromRoutingTable()
		if err != nil {
			return nil, errors.Errorf("can't getProxyDialer() because HostileNetworkEnvironmentEvasionSOCKS5Address was set to '%s' but: \n%+v\n", socks5Address, err)
		}
		if len(defaultGateways) == 0 {
			return nil, errors.Errorf(
				"can't getProxyDialer() because HostileNetworkEnvironmentEvasionSOCKS5Address was set to '%s' but no default gateways were found in routing table",
				socks5Address,
			)
		}

		failures := make([]string, len(defaultGateways))
		for i := 0; i < len(defaultGateways); i++ {
			address := fmt.Sprintf("%s:%s", defaultGateways[i], port)
			conn, err := net.Dial("tcp", address)
			if err == nil {
				conn.Close()
				return proxy.SOCKS5("tcp", address, nil, proxy.Direct)
			}
			failures = append(failures, fmt.Sprintf("can't connect to %s", address))
		}

		// if we got this far it means we tried them all and none of them worked.
		return nil, errors.Errorf("can't connect to HostileNetworkEnvironmentEvasionSOCKS5Address '%s': %s", socks5Address, strings.Join(failures, ", "))
	} else {
		conn, err := net.Dial("tcp", socks5Address)
		if err != nil {
			return nil, errors.Errorf("can't connect to HostileNetworkEnvironmentEvasionSOCKS5Address '%s': %s", socks5Address, err)
		}
		conn.Close()

		return proxy.SOCKS5("tcp", socks5Address, nil, proxy.Direct)
	}
}

// https://stackoverflow.com/questions/40682760/what-syscall-method-could-i-use-to-get-the-default-network-gateway
func getDefaultGatewaysFromRoutingTable() ([]string, error) {

	if runtime.GOOS != "linux" {
		return nil, errors.Errorf("getDefaultGatewaysFromRoutingTable() does not support %s operating system yet.", runtime.GOOS)
	}
	toReturn := []string{}

	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() { // skip the first line (header)
		for scanner.Scan() {
			tokens := strings.Split(scanner.Text(), "\t")
			destinationHex := "0x" + tokens[1]
			gatewayHex := "0x" + tokens[2]

			destinationInt, err := strconv.ParseInt(destinationHex, 0, 64)
			if err != nil {
				return nil, err
			}
			gatewayInt, err := strconv.ParseInt(gatewayHex, 0, 64)
			if err != nil {
				return nil, err
			}
			// 0 means 0.0.0.0 -- we are looking for default routes, routes that have universal destination 0.0.0.0
			if destinationInt == 0 && gatewayInt != 0 {
				gatewayUint32 := uint32(gatewayInt)

				// make net.IP address from uint32
				ip := make(net.IP, 4)
				binary.LittleEndian.PutUint32(ip, gatewayUint32)

				toReturn = append(toReturn, ip.String())
				//fmt.Printf("%T --> %[1]v\n", ipBytes)
			}
		}
	}

	return toReturn, nil
}
