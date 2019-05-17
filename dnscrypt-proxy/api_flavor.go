package main

import (
	"net"
	"time"

	clocksmith "github.com/jedisct1/go-clocksmith"
	"github.com/miekg/dns"
)

func (proxy *Proxy) StopProxy() {
	close(proxy.quitListeners)
	proxy.wgQuit.Wait()
}

func (proxy *Proxy) GetPluginsGlobals() *PluginsGlobals {
	return &proxy.pluginsGlobals
}

func (proxy *Proxy) GetIOSMode() bool {
	return proxy.iosMode
}

func (proxy *Proxy) GetPluginBlockIPv6() bool {
	return proxy.pluginBlockIPv6
}

func (proxy *Proxy) GetCloakFile() string {
	return proxy.cloakFile
}

func (proxy *Proxy) GetForwardFile() string {
	return proxy.forwardFile
}

func (proxy *Proxy) GetNXLogFile() string {
	return proxy.nxLogFile
}

func (proxy *Proxy) GetBlockIPFile() string {
	return proxy.blockIPFile
}

func (proxy *Proxy) GetBlockIPLogFile() string {
	return proxy.blockIPLogFile
}

func (proxy *Proxy) GetBlockIPFormat() string {
	return proxy.blockIPFormat
}

func (proxy *Proxy) GetQueryLogFile() string {
	return proxy.queryLogFile
}

func (proxy *Proxy) GetCache() bool {
	return proxy.cache
}

func (proxy *Proxy) GetBlockNameFile() string {
	return proxy.blockNameFile
}

func (proxy *Proxy) GetWhitelistNameFile() string {
	return proxy.whitelistNameFile
}

func (proxy *Proxy) GetWhitelistNameFormat() string {
	return proxy.whitelistNameFormat
}

func (proxy *Proxy) GetBlockNameFormat() string {
	return proxy.blockNameFormat
}

func (proxy *Proxy) GetBlockNameLogFile() string {
	return proxy.blockNameLogFile
}

func (proxy *Proxy) GetWhitelistNameLogFile() string {
	return proxy.whitelistNameLogFile
}

func (proxy *Proxy) GetLogMaxSize() int {
	return proxy.logMaxSize
}

func (proxy *Proxy) GetLogMaxAge() int {
	return proxy.logMaxAge
}

func (proxy *Proxy) GetLogMaxBackups() int {
	return proxy.logMaxBackups
}

func (proxy *Proxy) GetAllWeeklyRanges() *map[string]WeeklyRanges {
	return proxy.allWeeklyRanges
}

func (pluginsGlobals *PluginsGlobals) SetQueryPlugins(plugins *[]Plugin) {
	(*pluginsGlobals).queryPlugins = plugins
}

func (pluginsGlobals *PluginsGlobals) SetResponsePlugins(plugins *[]Plugin) {
	(*pluginsGlobals).responsePlugins = plugins
}

func (pluginsGlobals *PluginsGlobals) SetLoggingPlugins(plugins *[]Plugin) {
	(*pluginsGlobals).loggingPlugins = plugins
}

func (pluginsState *PluginsState) GetSessionDataKey(key string) interface{} {
	return pluginsState.sessionData[key]
}

func (pluginsState *PluginsState) SetSessionDataKey(key string, val interface{}) {
	if pluginsState.sessionData == nil {
		pluginsState.sessionData = make(map[string]interface{})
	}
	pluginsState.sessionData[key] = val
}

func (pluginsState *PluginsState) GetClientProto() string {
	return pluginsState.clientProto
}

func (pluginsState *PluginsState) GetClientAddr() *net.Addr {
	return pluginsState.clientAddr
}

func (pluginsState *PluginsState) SetAction(action PluginsAction) {
	pluginsState.action = action
}

func (pluginsState *PluginsState) SetReturnCode(code PluginsReturnCode) {
	pluginsState.returnCode = code
}

func RefusedResponseFromQuery(packet []byte, refusedCode bool) (*dns.Msg, error) {
	msg := dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		return nil, err
	}

	return RefusedResponseFromMessage(&msg, refusedCode)
}

func (xTransport *XTransport) SetupXTransportCloak(useIPv4 bool, useIPv6 bool, fallbackResolver string, ignoreSystemDNS bool) {
	xTransport.useIPv4 = useIPv4
	xTransport.useIPv6 = useIPv6
	xTransport.fallbackResolver = fallbackResolver
	xTransport.ignoreSystemDNS = ignoreSystemDNS
	xTransport.rebuildTransport()
}

func PrefetchSourceURLCloak(xTransport *XTransport, url string, cacheFile string) error {
	u := URLToPrefetch{url: url, cacheFile: cacheFile, when: time.Now()}
	return PrefetchSourceURL(xTransport, &u)
}

func RefreshServersInfoCloak(proxy *Proxy) {
	liveServers, _ := proxy.serversInfo.refresh(proxy)
	if liveServers > 0 {
		return
	}

	for proxy.serversInfo.liveServers() == 0 {
		delay := proxy.certRefreshDelayAfterFailure
		clocksmith.Sleep(delay)
		proxy.serversInfo.refresh(proxy)
	}
}

func DefaultConfig() Config {
	return newConfig()
}
