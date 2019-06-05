package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
	netproxy "golang.org/x/net/proxy"
)

const (
	MaxTimeout             = 3600
	DefaultNetprobeAddress = "9.9.9.9:53"
)

type Config struct {
	LogLevel                 int                        `toml:"log_level,omitempty" json:"log_level,omitempty"`
	LogFile                  *string                    `toml:"log_file,omitempty" json:"log_file,omitempty"`
	UseSyslog                bool                       `toml:"use_syslog,omitempty" json:"use_syslog,omitempty"`
	ServerNames              []string                   `toml:"server_names,omitempty" json:"server_names,omitempty"`
	DisabledServerNames      []string                   `toml:"disabled_server_names,omitempty" json:"disabled_server_names,omitempty"`
	ListenAddresses          []string                   `toml:"listen_addresses,omitempty" json:"listen_addresses,omitempty"`
	Daemonize                bool                       `toml:"-" json:"-"`
	UserName                 string                     `toml:"user_name,omitempty" json:"user_name,omitempty"`
	ForceTCP                 bool                       `toml:"force_tcp,omitempty" json:"force_tcp,omitempty"`
	Timeout                  int                        `toml:"timeout,omitempty" json:"timeout,omitempty"`
	KeepAlive                int                        `toml:"keepalive,omitempty" json:"keepalive,omitempty"`
	Proxy                    string                     `toml:"proxy,omitempty" json:"proxy,omitempty"`
	CertRefreshDelay         int                        `toml:"cert_refresh_delay,omitempty" json:"cert_refresh_delay,omitempty"`
	CertIgnoreTimestamp      bool                       `toml:"cert_ignore_timestamp,omitempty" json:"cert_ignore_timestamp,omitempty"`
	EphemeralKeys            bool                       `toml:"dnscrypt_ephemeral_keys,omitempty" json:"dnscrypt_ephemeral_keys,omitempty"`
	LBStrategy               string                     `toml:"lb_strategy,omitempty" json:"lb_strategy,omitempty"`
    LBEstimator              bool                       `toml:"lb_estimator,omitempty" json:"lb_estimator,omitempty"`
	BlockIPv6                bool                       `toml:"block_ipv6,omitempty" json:"block_ipv6,omitempty"`
	Cache                    bool                       `toml:"cache,omitempty" json:"cache,omitempty"`
	CacheSize                int                        `toml:"cache_size,omitempty" json:"cache_size,omitempty"`
	CacheNegTTL              uint32                     `toml:"cache_neg_ttl,omitempty" json:"cache_neg_ttl,omitempty"`
	CacheNegMinTTL           uint32                     `toml:"cache_neg_min_ttl,omitempty" json:"cache_neg_min_ttl,omitempty"`
	CacheNegMaxTTL           uint32                     `toml:"cache_neg_max_ttl,omitempty" json:"cache_neg_max_ttl,omitempty"`
	CacheMinTTL              uint32                     `toml:"cache_min_ttl,omitempty" json:"cache_min_ttl,omitempty"`
	CacheMaxTTL              uint32                     `toml:"cache_max_ttl,omitempty" json:"cache_max_ttl,omitempty"`
	QueryLog                 QueryLogConfig             `toml:"query_log,omitempty" json:"query_log,omitempty"`
	NxLog                    NxLogConfig                `toml:"nx_log,omitempty" json:"nx_log,omitempty"`
	BlockName                BlockNameConfig            `toml:"blacklist,omitempty" json:"blacklist,omitempty"`
	WhitelistName            WhitelistNameConfig        `toml:"whitelist,omitempty" json:"whitelist,omitempty"`
	BlockIP                  BlockIPConfig              `toml:"ip_blacklist,omitempty" json:"ip_blacklist,omitempty"`
	ForwardFile              string                     `toml:"forwarding_rules,omitempty" json:"forwarding_rules,omitempty"`
	CloakFile                string                     `toml:"cloaking_rules,omitempty" json:"cloaking_rules,omitempty"`
	ServersConfig            map[string]StaticConfig    `toml:"static,omitempty" json:"static,omitempty"`
	SourcesConfig            map[string]SourceConfig    `toml:"sources,omitempty" json:"sources,omitempty"`
	SourceRequireDNSSEC      bool                       `toml:"require_dnssec,omitempty" json:"require_dnssec,omitempty"`
	SourceRequireNoLog       bool                       `toml:"require_nolog,omitempty" json:"require_nolog,omitempty"`
	SourceRequireNoFilter    bool                       `toml:"require_nofilter,omitempty" json:"require_nofilter,omitempty"`
	SourceDNSCrypt           bool                       `toml:"dnscrypt_servers,omitempty" json:"dnscrypt_servers,omitempty"`
	SourceDoH                bool                       `toml:"doh_servers,omitempty" json:"doh_servers,omitempty"`
	SourceIPv4               bool                       `toml:"ipv4_servers,omitempty" json:"ipv4_servers,omitempty"`
	SourceIPv6               bool                       `toml:"ipv6_servers,omitempty" json:"ipv6_servers,omitempty"`
	MaxClients               uint32                     `toml:"max_clients,omitempty" json:"max_clients,omitempty"`
	FallbackResolver         string                     `toml:"fallback_resolver,omitempty" json:"fallback_resolver,omitempty"`
	IgnoreSystemDNS          bool                       `toml:"ignore_system_dns,omitempty" json:"ignore_system_dns,omitempty"`
	AllWeeklyRanges          map[string]WeeklyRangesStr `toml:"schedules,omitempty" json:"schedules,omitempty"`
	LogMaxSize               int                        `toml:"log_files_max_size,omitempty" json:"log_files_max_size,omitempty"`
	LogMaxAge                int                        `toml:"log_files_max_age,omitempty" json:"log_files_max_age,omitempty"`
	LogMaxBackups            int                        `toml:"log_files_max_backups,omitempty" json:"log_files_max_backups,omitempty"`
	TLSDisableSessionTickets bool                       `toml:"tls_disable_session_tickets,omitempty" json:"tls_disable_session_tickets,omitempty"`
	TLSCipherSuite           []uint16                   `toml:"tls_cipher_suite,omitempty" json:"tls_cipher_suite,omitempty"`
	NetprobeAddress          string                     `toml:"netprobe_address,omitempty" json:"netprobe_address,omitempty"`
	NetprobeTimeout          int                        `toml:"netprobe_timeout,omitempty" json:"netprobe_timeout,omitempty"`
	MaxWorkers               int                        `toml:"max_workers,omitempty" json:"max_workers,omitempty"`
	RetryCount               int                        `toml:"retry_count,omitempty" json:"retry_count,omitempty"`
	IOSMode                  bool                       `toml:"ios_mode,omitempty" json:"ios_mode,omitempty"`
	OfflineMode              bool                       `toml:"offline_mode,omitempty" json:"offline_mode,omitempty"`
	HTTPProxyURL             string                     `toml:"http_proxy,omitempty" json:"http_proxy,omitempty"`
	RefusedCodeInResponses   bool                       `toml:"refused_code_in_responses,omitempty" json:"refused_code_in_responses,omitempty"`
}

func newConfig() Config {
	return Config{
		LogLevel:                 int(dlog.LogLevel()),
		ListenAddresses:          []string{"127.0.0.1:53"},
		Timeout:                  2500,
		KeepAlive:                5,
		CertRefreshDelay:         240,
		CertIgnoreTimestamp:      false,
		EphemeralKeys:            false,
		Cache:                    true,
		CacheSize:                512,
		CacheNegTTL:              0,
		CacheNegMinTTL:           60,
		CacheNegMaxTTL:           600,
		CacheMinTTL:              60,
		CacheMaxTTL:              8600,
		SourceRequireNoLog:       true,
		SourceRequireNoFilter:    true,
		SourceIPv4:               true,
		SourceIPv6:               false,
		SourceDNSCrypt:           true,
		SourceDoH:                true,
		MaxClients:               250,
		FallbackResolver:         DefaultFallbackResolver,
		IgnoreSystemDNS:          false,
		LogMaxSize:               10,
		LogMaxAge:                7,
		LogMaxBackups:            1,
		TLSDisableSessionTickets: false,
		TLSCipherSuite:           nil,
		NetprobeTimeout:          60,
		OfflineMode:              false,
		RefusedCodeInResponses:   false,
		LBEstimator:              true,
		MaxWorkers:               25,
		RetryCount:               5,
		IOSMode:                  true,
	}
}

type StaticConfig struct {
	Stamp string `toml:"stamp,omitempty" json:"stamp,omitempty"`
}

type SourceConfig struct {
	URL            string   `toml:"url,omitempty" json:"url,omitempty"`
	URLs           []string `toml:"urls,omitempty" json:"urls,omitempty"`
	MinisignKeyStr string   `toml:"minisign_key,omitempty" json:"minisign_key,omitempty"`
	CacheFile      string   `toml:"cache_file,omitempty" json:"cache_file,omitempty"`
	FormatStr      string   `toml:"format,omitempty" json:"format,omitempty"`
	RefreshDelay   int      `toml:"refresh_delay,omitempty" json:"refresh_delay,omitempty"`
	Prefix         string   `toml:"prefix,omitempty" json:"prefix,omitempty"`
}

type QueryLogConfig struct {
	File          string   `toml:"file,omitempty" json:"file,omitempty"`
	Format        string   `toml:"format,omitempty" json:"format,omitempty"`
	IgnoredQtypes []string `toml:"ignored_qtypes,omitempty" json:"ignored_qtypes,omitempty"`
}

type NxLogConfig struct {
	File   string `toml:"file,omitempty" json:"file,omitempty"`
	Format string `toml:"format,omitempty" json:"format,omitempty"`
}

type BlockNameConfig struct {
	File    string `toml:"blacklist_file,omitempty" json:"blacklist_file,omitempty"`
	LogFile string `toml:"log_file,omitempty" json:"log_file,omitempty"`
	Format  string `toml:"log_format,omitempty" json:"log_format,omitempty"`
}

type WhitelistNameConfig struct {
	File    string `toml:"whitelist_file,omitempty" json:"whitelist_file,omitempty"`
	LogFile string `toml:"log_file,omitempty" json:"log_file,omitempty"`
	Format  string `toml:"log_format,omitempty" json:"log_format,omitempty"`
}

type BlockIPConfig struct {
	File    string `toml:"blacklist_file,omitempty" json:"blacklist_file,omitempty"`
	LogFile string `toml:"log_file,omitempty" json:"log_file,omitempty"`
	Format  string `toml:"log_format,omitempty" json:"log_format,omitempty"`
}

type ServerSummary struct {
	Name        string   `json:"name"`
	Proto       string   `json:"proto"`
	IPv6        bool     `json:"ipv6"`
	Addrs       []string `json:"addrs,omitempty"`
	Ports       []int    `json:"ports"`
	DNSSEC      bool     `json:"dnssec"`
	NoLog       bool     `json:"nolog"`
	NoFilter    bool     `json:"nofilter"`
	Description string   `json:"description,omitempty"`
}

func findConfigFile(configFile *string) (string, error) {
	if _, err := os.Stat(*configFile); os.IsNotExist(err) {
		cdLocal(*configFile)
		if _, err := os.Stat(*configFile); err != nil {
			return "", err
		}
	}
	pwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if filepath.IsAbs(*configFile) {
		return *configFile, nil
	}
	return path.Join(pwd, *configFile), nil
}

func ConfigLoad(proxy *Proxy, svcFlag *string, configFilePath string) error {
	version := flag.Bool("version", false, "print current proxy version")
	resolve := flag.String("resolve", "", "resolve a name using system libraries")
	list := flag.Bool("list", false, "print the list of available resolvers for the enabled filters")
	listAll := flag.Bool("list-all", false, "print the complete list of available resolvers, ignoring filters")
	jsonOutput := flag.Bool("json", false, "output list as JSON")
	check := flag.Bool("check", false, "check the configuration file and exit")
	configFile := flag.String("config", configFilePath, "Path to the configuration file")
	child := flag.Bool("child", false, "Invokes program as a child process")
	netprobeTimeoutOverride := flag.Int("netprobe-timeout", 60, "Override the netprobe timeout")

	flag.Parse()

	if *svcFlag == "stop" || *svcFlag == "uninstall" {
		return nil
	}
	if *version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}
	if resolve != nil && len(*resolve) > 0 {
		Resolve(*resolve)
		os.Exit(0)
	}

	foundConfigFile, err := findConfigFile(configFile)
	if err != nil {
		dlog.Fatalf("Unable to load the configuration file [%s] -- Maybe use the -config command-line switch?", *configFile)
	}
	config := newConfig()
	md, err := toml.DecodeFile(foundConfigFile, &config)
	if err != nil {
		return err
	}
	undecoded := md.Undecoded()
	if len(undecoded) > 0 {
		return fmt.Errorf("Unsupported key in configuration file: [%s]", undecoded[0])
	}
	cdFileDir(foundConfigFile)
	if config.LogLevel >= 0 && config.LogLevel < int(dlog.SeverityLast) {
		dlog.SetLogLevel(dlog.Severity(config.LogLevel))
	}
	/*if dlog.LogLevel() <= dlog.SeverityDebug && os.Getenv("DEBUG") == "" {
		dlog.SetLogLevel(dlog.SeverityInfo)
	}*/
	if config.UseSyslog {
		dlog.UseSyslog(true)
	} else if config.LogFile != nil {
		dlog.UseLogFile(*config.LogFile)
		if !*child {
			FileDescriptors = append(FileDescriptors, dlog.GetFileDescriptor())
		} else {
			FileDescriptorNum++
			dlog.SetFileDescriptor(os.NewFile(uintptr(3), "logFile"))
		}
	}
	proxy.logMaxSize = config.LogMaxSize
	proxy.logMaxAge = config.LogMaxAge
	proxy.logMaxBackups = config.LogMaxBackups

	proxy.userName = config.UserName

	proxy.child = *child
	proxy.xTransport = NewXTransport()
	proxy.xTransport.tlsDisableSessionTickets = config.TLSDisableSessionTickets
	proxy.xTransport.tlsCipherSuite = config.TLSCipherSuite
	proxy.xTransport.fallbackResolver = config.FallbackResolver
	if len(config.FallbackResolver) > 0 {
		proxy.xTransport.ignoreSystemDNS = config.IgnoreSystemDNS
	}
	proxy.xTransport.useIPv4 = config.SourceIPv4
	proxy.xTransport.useIPv6 = config.SourceIPv6
	proxy.xTransport.keepAlive = time.Duration(config.KeepAlive) * time.Second
	if len(config.HTTPProxyURL) > 0 {
		httpProxyURL, err := url.Parse(config.HTTPProxyURL)
		if err != nil {
			dlog.Fatalf("Unable to parse the HTTP proxy URL [%v]", config.HTTPProxyURL)
		}
		proxy.xTransport.httpProxyFunction = http.ProxyURL(httpProxyURL)
	}

	if len(config.Proxy) > 0 {
		proxyDialerURL, err := url.Parse(config.Proxy)
		if err != nil {
			dlog.Fatalf("Unable to parse the proxy URL [%v]", config.Proxy)
		}
		proxyDialer, err := netproxy.FromURL(proxyDialerURL, netproxy.Direct)
		if err != nil {
			dlog.Fatalf("Unable to use the proxy: [%v]", err)
		}
		proxy.xTransport.proxyDialer = &proxyDialer
		proxy.mainProto = "tcp"
	}

	proxy.xTransport.rebuildTransport()

	proxy.refusedCodeInResponses = config.RefusedCodeInResponses
	proxy.timeout = time.Duration(config.Timeout) * time.Millisecond
	proxy.maxClients = config.MaxClients

	proxy.iosMode = config.IOSMode
	proxy.retryCount = config.RetryCount

	proxy.maxWorkers = config.MaxWorkers

	proxy.mainProto = "udp"
	if config.ForceTCP {
		proxy.mainProto = "tcp"
	}
	proxy.certRefreshDelay = time.Duration(config.CertRefreshDelay) * time.Minute
	proxy.certRefreshDelayAfterFailure = time.Duration(10 * time.Second)
	proxy.certIgnoreTimestamp = config.CertIgnoreTimestamp
	proxy.ephemeralKeys = config.EphemeralKeys
	if len(config.ListenAddresses) == 0 {
		dlog.Debug("No local IP/port configured")
	}

	lbStrategy := DefaultLBStrategy
	switch strings.ToLower(config.LBStrategy) {
	case "":
		// default
	case "p2":
		lbStrategy = LBStrategyP2
	case "ph":
		lbStrategy = LBStrategyPH
	case "fastest":
	case "first":
		lbStrategy = LBStrategyFirst
	case "random":
		lbStrategy = LBStrategyRandom
	default:
		dlog.Warnf("Unknown load balancing strategy: [%s]", config.LBStrategy)
	}
	proxy.serversInfo.lbStrategy = lbStrategy
	proxy.serversInfo.lbEstimator = config.LBEstimator

	proxy.listenAddresses = config.ListenAddresses
	proxy.daemonize = config.Daemonize
	proxy.pluginBlockIPv6 = config.BlockIPv6
	proxy.cache = config.Cache
	proxy.cacheSize = config.CacheSize

	if config.CacheNegTTL > 0 {
		proxy.cacheNegMinTTL = config.CacheNegTTL
		proxy.cacheNegMaxTTL = config.CacheNegTTL
	} else {
		proxy.cacheNegMinTTL = config.CacheNegMinTTL
		proxy.cacheNegMaxTTL = config.CacheNegMaxTTL
	}

	proxy.cacheMinTTL = config.CacheMinTTL
	proxy.cacheMaxTTL = config.CacheMaxTTL

	if len(config.QueryLog.Format) == 0 {
		config.QueryLog.Format = "tsv"
	} else {
		config.QueryLog.Format = strings.ToLower(config.QueryLog.Format)
	}
	if config.QueryLog.Format != "tsv" && config.QueryLog.Format != "ltsv" {
		return errors.New("Unsupported query log format")
	}
	proxy.queryLogFile = config.QueryLog.File
	proxy.queryLogFormat = config.QueryLog.Format
	proxy.queryLogIgnoredQtypes = config.QueryLog.IgnoredQtypes

	if len(config.NxLog.Format) == 0 {
		config.NxLog.Format = "tsv"
	} else {
		config.NxLog.Format = strings.ToLower(config.NxLog.Format)
	}
	if config.NxLog.Format != "tsv" && config.NxLog.Format != "ltsv" {
		return errors.New("Unsupported NX log format")
	}
	proxy.nxLogFile = config.NxLog.File
	proxy.nxLogFormat = config.NxLog.Format

	if len(config.BlockName.Format) == 0 {
		config.BlockName.Format = "tsv"
	} else {
		config.BlockName.Format = strings.ToLower(config.BlockName.Format)
	}
	if config.BlockName.Format != "tsv" && config.BlockName.Format != "ltsv" {
		return errors.New("Unsupported block log format")
	}
	proxy.blockNameFile = config.BlockName.File
	proxy.blockNameFormat = config.BlockName.Format
	proxy.blockNameLogFile = config.BlockName.LogFile

	if len(config.WhitelistName.Format) == 0 {
		config.WhitelistName.Format = "tsv"
	} else {
		config.WhitelistName.Format = strings.ToLower(config.WhitelistName.Format)
	}
	if config.WhitelistName.Format != "tsv" && config.WhitelistName.Format != "ltsv" {
		return errors.New("Unsupported whitelist log format")
	}
	proxy.whitelistNameFile = config.WhitelistName.File
	proxy.whitelistNameFormat = config.WhitelistName.Format
	proxy.whitelistNameLogFile = config.WhitelistName.LogFile

	if len(config.BlockIP.Format) == 0 {
		config.BlockIP.Format = "tsv"
	} else {
		config.BlockIP.Format = strings.ToLower(config.BlockIP.Format)
	}
	if config.BlockIP.Format != "tsv" && config.BlockIP.Format != "ltsv" {
		return errors.New("Unsupported IP block log format")
	}
	proxy.blockIPFile = config.BlockIP.File
	proxy.blockIPFormat = config.BlockIP.Format
	proxy.blockIPLogFile = config.BlockIP.LogFile

	proxy.forwardFile = config.ForwardFile
	proxy.cloakFile = config.CloakFile

	allWeeklyRanges, err := ParseAllWeeklyRanges(config.AllWeeklyRanges)
	if err != nil {
		return err
	}
	proxy.allWeeklyRanges = allWeeklyRanges

	if *listAll {
		config.ServerNames = nil
		config.DisabledServerNames = nil
		config.SourceRequireDNSSEC = false
		config.SourceRequireNoFilter = false
		config.SourceRequireNoLog = false
		config.SourceIPv4 = true
		config.SourceIPv6 = true
		config.SourceDNSCrypt = true
		config.SourceDoH = true
	}

	netprobeTimeout := config.NetprobeTimeout
	flag.Visit(func(flag *flag.Flag) {
		if flag.Name == "netprobe-timeout" && netprobeTimeoutOverride != nil {
			netprobeTimeout = *netprobeTimeoutOverride
		}
	})
	netprobeAddress := DefaultNetprobeAddress
	if len(config.NetprobeAddress) > 0 {
		netprobeAddress = config.NetprobeAddress
	} else if len(config.FallbackResolver) > 0 {
		netprobeAddress = config.FallbackResolver
	}
	NetProbe(netprobeAddress, netprobeTimeout)
	if !config.OfflineMode {
		if err := config.loadSources(proxy); err != nil {
			return err
		}
		if len(proxy.registeredServers) == 0 {
			return errors.New("No servers configured")
		}
	}
	if *list || *listAll {
		config.printRegisteredServers(proxy, *jsonOutput)
		os.Exit(0)
	}
	if *check {
		dlog.Notice("Configuration successfully checked")
		os.Exit(0)
	}
	return nil
}

func (config *Config) printRegisteredServers(proxy *Proxy, jsonOutput bool) {
	var summary []ServerSummary
	for _, registeredServer := range proxy.registeredServers {
		addrStr, port := registeredServer.stamp.ServerAddrStr, stamps.DefaultPort
		port = ExtractPort(addrStr, port)
		addrs := make([]string, 0)
		if registeredServer.stamp.Proto == stamps.StampProtoTypeDoH && len(registeredServer.stamp.ProviderName) > 0 {
			providerName := registeredServer.stamp.ProviderName
			var host string
			host, port = ExtractHostAndPort(providerName, port)
			addrs = append(addrs, host)
		}
		if len(addrStr) > 0 {
			addrs = append(addrs, ExtractHost(addrStr))
		}
		serverSummary := ServerSummary{
			Name:        registeredServer.name,
			Proto:       registeredServer.stamp.Proto.String(),
			IPv6:        strings.HasPrefix(addrStr, "["),
			Ports:       []int{port},
			Addrs:       addrs,
			DNSSEC:      registeredServer.stamp.Props&stamps.ServerInformalPropertyDNSSEC != 0,
			NoLog:       registeredServer.stamp.Props&stamps.ServerInformalPropertyNoLog != 0,
			NoFilter:    registeredServer.stamp.Props&stamps.ServerInformalPropertyNoFilter != 0,
			Description: registeredServer.description,
		}
		if jsonOutput {
			summary = append(summary, serverSummary)
		} else {
			fmt.Println(serverSummary.Name)
		}
	}
	if jsonOutput {
		jsonStr, err := json.MarshalIndent(summary, "", " ")
		if err != nil {
			dlog.Fatal(err)
		}
		fmt.Print(string(jsonStr))
	}
}

func (config *Config) loadSources(proxy *Proxy) error {
	var requiredProps stamps.ServerInformalProperties
	if config.SourceRequireDNSSEC {
		requiredProps |= stamps.ServerInformalPropertyDNSSEC
	}
	if config.SourceRequireNoLog {
		requiredProps |= stamps.ServerInformalPropertyNoLog
	}
	if config.SourceRequireNoFilter {
		requiredProps |= stamps.ServerInformalPropertyNoFilter
	}
	for cfgSourceName, cfgSource := range config.SourcesConfig {
		if err := config.loadSource(proxy, requiredProps, cfgSourceName, &cfgSource); err != nil {
			return err
		}
	}
	if len(config.ServerNames) == 0 {
		for serverName := range config.ServersConfig {
			config.ServerNames = append(config.ServerNames, serverName)
		}
	}
	for _, serverName := range config.ServerNames {
		staticConfig, ok := config.ServersConfig[serverName]
		if !ok {
			continue
		}
		if len(staticConfig.Stamp) == 0 {
			dlog.Fatalf("Missing stamp for the static [%s] definition", serverName)
		}
		stamp, err := stamps.NewServerStampFromString(staticConfig.Stamp)
		if err != nil {
			return err
		}
		proxy.registeredServers = append(proxy.registeredServers, RegisteredServer{name: serverName, stamp: stamp})
	}
	rand.Shuffle(len(proxy.registeredServers), func(i, j int) {
		proxy.registeredServers[i], proxy.registeredServers[j] = proxy.registeredServers[j], proxy.registeredServers[i]
	})

	return nil
}

func (config *Config) loadSource(proxy *Proxy, requiredProps stamps.ServerInformalProperties, cfgSourceName string, cfgSource *SourceConfig) error {
	if len(cfgSource.URLs) == 0 {
		if len(cfgSource.URL) == 0 {
			dlog.Debugf("Missing URLs for source [%s]", cfgSourceName)
		} else {
			cfgSource.URLs = []string{cfgSource.URL}
		}
	}
	if cfgSource.MinisignKeyStr == "" {
		return fmt.Errorf("Missing Minisign key for source [%s]", cfgSourceName)
	}
	if cfgSource.CacheFile == "" {
		return fmt.Errorf("Missing cache file for source [%s]", cfgSourceName)
	}
	if cfgSource.FormatStr == "" {
		cfgSource.FormatStr = "v2"
	}
	if cfgSource.RefreshDelay <= 0 {
		cfgSource.RefreshDelay = 72
	}
	source, sourceUrlsToPrefetch, err := NewSource(proxy.xTransport, cfgSource.URLs, cfgSource.MinisignKeyStr, cfgSource.CacheFile, cfgSource.FormatStr, time.Duration(cfgSource.RefreshDelay)*time.Hour)
	proxy.urlsToPrefetch = append(proxy.urlsToPrefetch, sourceUrlsToPrefetch...)
	if err != nil {
		dlog.Criticalf("Unable to retrieve source [%s]: [%s]", cfgSourceName, err)
		return err
	}
	registeredServers, err := source.Parse(cfgSource.Prefix)
	if err != nil {
		dlog.Criticalf("Unable to use source [%s]: [%s]", cfgSourceName, err)
		return err
	}
	for _, registeredServer := range registeredServers {
		if len(config.ServerNames) > 0 {
			if !includesName(config.ServerNames, registeredServer.name) {
				continue
			}
		} else if registeredServer.stamp.Props&requiredProps != requiredProps {
			continue
		}
		if includesName(config.DisabledServerNames, registeredServer.name) {
			continue
		}
		if config.SourceIPv4 || config.SourceIPv6 {
			isIPv4, isIPv6 := true, false
			if registeredServer.stamp.Proto == stamps.StampProtoTypeDoH {
				isIPv4, isIPv6 = true, true
			}
			if strings.HasPrefix(registeredServer.stamp.ServerAddrStr, "[") {
				isIPv4, isIPv6 = false, true
			}
			if !(config.SourceIPv4 == isIPv4 || config.SourceIPv6 == isIPv6) {
				continue
			}
		}
		if !((config.SourceDNSCrypt && registeredServer.stamp.Proto == stamps.StampProtoTypeDNSCrypt) ||
			(config.SourceDoH && registeredServer.stamp.Proto == stamps.StampProtoTypeDoH)) {
			continue
		}
		dlog.Debugf("Adding [%s] to the set of wanted resolvers", registeredServer.name)
		proxy.registeredServers = append(proxy.registeredServers, registeredServer)
	}
	return nil
}

func includesName(names []string, name string) bool {
	for _, found := range names {
		if strings.EqualFold(found, name) {
			return true
		}
	}
	return false
}

func cdFileDir(fileName string) {
	os.Chdir(filepath.Dir(fileName))
}

func cdLocal(ex string) {
	os.Chdir(filepath.Dir(ex))
}
