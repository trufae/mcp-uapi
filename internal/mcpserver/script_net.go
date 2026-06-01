package mcpserver

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	stdio "io"
	stdnet "net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dop251/goja"
)

type netConnEntry struct {
	Handle  string      `json:"handle"`
	Network string      `json:"network"`
	Conn    stdnet.Conn `json:"-"`
}

type netListenerEntry struct {
	Handle   string          `json:"handle"`
	Network  string          `json:"network"`
	Listener stdnet.Listener `json:"-"`
}

type netPacketConnEntry struct {
	Handle     string            `json:"handle"`
	Network    string            `json:"network"`
	PacketConn stdnet.PacketConn `json:"-"`
}

type scriptNetConnRef struct {
	Conn   string `json:"conn"`
	Handle string `json:"handle"`
}

type scriptNetListenerRef struct {
	Listener string `json:"listener"`
	Handle   string `json:"handle"`
}

type scriptNetPacketConnRef struct {
	Packet string `json:"packet"`
	Handle string `json:"handle"`
}

func (r scriptNetConnRef) handle() string {
	if r.Conn != "" {
		return r.Conn
	}
	return r.Handle
}

func (r scriptNetListenerRef) handle() string {
	if r.Listener != "" {
		return r.Listener
	}
	return r.Handle
}

func (r scriptNetPacketConnRef) handle() string {
	if r.Packet != "" {
		return r.Packet
	}
	return r.Handle
}

func (e *scriptEnv) netObject() *goja.Object {
	obj := e.vm.NewObject()
	for _, method := range e.netMethods() {
		e.setScriptMethod(obj, method.JSName, method.Method)
		if method.GoName != "" && method.GoName != method.JSName {
			e.setScriptMethod(obj, method.GoName, method.Method)
		}
	}
	return obj
}

func (e *scriptEnv) netMethods() []scriptNamedMethod {
	return []scriptNamedMethod{
		{"Constants", "constants", e.scriptNetConstants},
		{"Dial", "dial", e.scriptNetDial},
		{"Listen", "listen", e.scriptNetListen},
		{"ListenPacket", "listenPacket", e.scriptNetListenPacket},
		{"Pipe", "pipe", e.scriptNetPipe},
		{"ResolveTCPAddr", "resolveTCPAddr", e.scriptNetResolveTCPAddr},
		{"ResolveUDPAddr", "resolveUDPAddr", e.scriptNetResolveUDPAddr},
		{"ResolveIPAddr", "resolveIPAddr", e.scriptNetResolveIPAddr},
		{"ResolveUnixAddr", "resolveUnixAddr", e.scriptNetResolveUnixAddr},
		{"LookupHost", "lookupHost", e.scriptNetLookupHost},
		{"LookupIP", "lookupIP", e.scriptNetLookupIP},
		{"LookupPort", "lookupPort", e.scriptNetLookupPort},
		{"LookupCNAME", "lookupCNAME", e.scriptNetLookupCNAME},
		{"LookupAddr", "lookupAddr", e.scriptNetLookupAddr},
		{"LookupMX", "lookupMX", e.scriptNetLookupMX},
		{"LookupNS", "lookupNS", e.scriptNetLookupNS},
		{"LookupTXT", "lookupTXT", e.scriptNetLookupTXT},
		{"LookupSRV", "lookupSRV", e.scriptNetLookupSRV},
		{"SplitHostPort", "splitHostPort", e.scriptNetSplitHostPort},
		{"JoinHostPort", "joinHostPort", e.scriptNetJoinHostPort},
		{"ParseIP", "parseIP", e.scriptNetParseIP},
		{"ParseCIDR", "parseCIDR", e.scriptNetParseCIDR},
		{"InterfaceAddrs", "interfaceAddrs", e.scriptNetInterfaceAddrs},
		{"Interfaces", "interfaces", e.scriptNetInterfaces},
		{"InterfaceByName", "interfaceByName", e.scriptNetInterfaceByName},
		{"InterfaceByIndex", "interfaceByIndex", e.scriptNetInterfaceByIndex},
		{"ConnRead", "connRead", e.scriptNetConnRead},
		{"ConnWrite", "connWrite", e.scriptNetConnWrite},
		{"ConnClose", "connClose", e.scriptNetConnClose},
		{"ConnLocalAddr", "connLocalAddr", e.scriptNetConnLocalAddr},
		{"ConnRemoteAddr", "connRemoteAddr", e.scriptNetConnRemoteAddr},
		{"ConnSetDeadline", "connSetDeadline", e.scriptNetConnSetDeadline},
		{"ConnSetReadDeadline", "connSetReadDeadline", e.scriptNetConnSetReadDeadline},
		{"ConnSetWriteDeadline", "connSetWriteDeadline", e.scriptNetConnSetWriteDeadline},
		{"TCPConnCloseRead", "tcpConnCloseRead", e.scriptNetTCPConnCloseRead},
		{"TCPConnCloseWrite", "tcpConnCloseWrite", e.scriptNetTCPConnCloseWrite},
		{"TCPConnSetKeepAlive", "tcpConnSetKeepAlive", e.scriptNetTCPConnSetKeepAlive},
		{"TCPConnSetKeepAlivePeriod", "tcpConnSetKeepAlivePeriod", e.scriptNetTCPConnSetKeepAlivePeriod},
		{"TCPConnSetNoDelay", "tcpConnSetNoDelay", e.scriptNetTCPConnSetNoDelay},
		{"ListenerAccept", "listenerAccept", e.scriptNetListenerAccept},
		{"ListenerClose", "listenerClose", e.scriptNetListenerClose},
		{"ListenerAddr", "listenerAddr", e.scriptNetListenerAddr},
		{"ListenerSetDeadline", "listenerSetDeadline", e.scriptNetListenerSetDeadline},
		{"PacketReadFrom", "packetReadFrom", e.scriptNetPacketReadFrom},
		{"PacketWriteTo", "packetWriteTo", e.scriptNetPacketWriteTo},
		{"PacketClose", "packetClose", e.scriptNetPacketClose},
		{"PacketLocalAddr", "packetLocalAddr", e.scriptNetPacketLocalAddr},
		{"PacketSetDeadline", "packetSetDeadline", e.scriptNetPacketSetDeadline},
		{"PacketSetReadDeadline", "packetSetReadDeadline", e.scriptNetPacketSetReadDeadline},
		{"PacketSetWriteDeadline", "packetSetWriteDeadline", e.scriptNetPacketSetWriteDeadline},
	}
}

func scriptNetWrapperNames() []string {
	return []string{
		"constants", "dial", "listen", "listenPacket", "pipe",
		"resolveTCPAddr", "resolveUDPAddr", "resolveIPAddr", "resolveUnixAddr",
		"lookupHost", "lookupIP", "lookupPort", "lookupCNAME", "lookupAddr", "lookupMX", "lookupNS", "lookupTXT", "lookupSRV",
		"splitHostPort", "joinHostPort", "parseIP", "parseCIDR", "interfaceAddrs", "interfaces", "interfaceByName", "interfaceByIndex",
		"connRead", "connWrite", "connClose", "connLocalAddr", "connRemoteAddr", "connSetDeadline", "connSetReadDeadline", "connSetWriteDeadline",
		"tcpConnCloseRead", "tcpConnCloseWrite", "tcpConnSetKeepAlive", "tcpConnSetKeepAlivePeriod", "tcpConnSetNoDelay",
		"listenerAccept", "listenerClose", "listenerAddr", "listenerSetDeadline",
		"packetReadFrom", "packetWriteTo", "packetClose", "packetLocalAddr", "packetSetDeadline", "packetSetReadDeadline", "packetSetWriteDeadline",
	}
}

func netConstants() map[string]any {
	return map[string]any{
		"networks":        []string{"tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "unix", "unixgram", "unixpacket", "ip", "ip4", "ip6"},
		"stream_networks": []string{"tcp", "tcp4", "tcp6", "unix", "unixpacket"},
		"packet_networks": []string{"udp", "udp4", "udp6", "unixgram", "ip", "ip4", "ip6"},
	}
}

func (e *scriptEnv) scriptNetConstants(value goja.Value) (any, error) {
	return map[string]any{"ok": true, "constants": netConstants()}, nil
}

func (e *scriptEnv) scriptNetDial(value goja.Value) (any, error) {
	var args struct {
		Network      string `json:"network"`
		Address      string `json:"address"`
		LocalAddress string `json:"local_address"`
		Handle       string `json:"handle"`
		TimeoutMS    Uint32 `json:"timeout_ms"`
		KeepAliveMS  *int64 `json:"keep_alive_ms"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	network := defaultNetwork(args.Network, "tcp")
	if strings.TrimSpace(args.Address) == "" {
		return nil, errors.New("address is required")
	}
	dialer := stdnet.Dialer{}
	if args.TimeoutMS != 0 {
		dialer.Timeout = timeoutDuration(args.TimeoutMS)
	}
	if args.KeepAliveMS != nil {
		dialer.KeepAlive = time.Duration(*args.KeepAliveMS) * time.Millisecond
	}
	if args.LocalAddress != "" {
		localAddr, err := resolveNetAddrForNetwork(network, args.LocalAddress)
		if err != nil {
			return nil, err
		}
		dialer.LocalAddr = localAddr
	}
	ctx, cancel := e.contextWithTimeout(args.TimeoutMS)
	defer cancel()
	conn, err := dialer.DialContext(ctx, network, args.Address)
	fields := map[string]any{"network": network, "address": args.Address}
	return e.registerNetConn(conn, network, args.Handle, fields, err)
}

func (e *scriptEnv) scriptNetListen(value goja.Value) (any, error) {
	var args struct {
		Network string `json:"network"`
		Address string `json:"address"`
		Handle  string `json:"handle"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	network := defaultNetwork(args.Network, "tcp")
	if strings.TrimSpace(args.Address) == "" {
		return nil, errors.New("address is required")
	}
	config := stdnet.ListenConfig{}
	listener, err := config.Listen(e.ctx, network, args.Address)
	fields := map[string]any{"network": network, "address": args.Address}
	return e.registerNetListener(listener, network, args.Handle, fields, err)
}

func (e *scriptEnv) scriptNetListenPacket(value goja.Value) (any, error) {
	var args struct {
		Network string `json:"network"`
		Address string `json:"address"`
		Handle  string `json:"handle"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	network := defaultNetwork(args.Network, "udp")
	if strings.TrimSpace(args.Address) == "" {
		return nil, errors.New("address is required")
	}
	config := stdnet.ListenConfig{}
	packet, err := config.ListenPacket(e.ctx, network, args.Address)
	fields := map[string]any{"network": network, "address": args.Address}
	return e.registerNetPacketConn(packet, network, args.Handle, fields, err)
}

func (e *scriptEnv) scriptNetPipe(value goja.Value) (any, error) {
	var args struct {
		Handles []string `json:"handles"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if len(args.Handles) != 0 && len(args.Handles) != 2 {
		return nil, errors.New("handles must contain exactly two names when provided")
	}
	leftHandle, rightHandle := "", ""
	if len(args.Handles) == 2 {
		leftHandle, rightHandle = args.Handles[0], args.Handles[1]
	}
	left, right := stdnet.Pipe()
	leftFields, err := e.registerNetConn(left, "pipe", leftHandle, map[string]any{"index": 0, "peer_index": 1}, nil)
	if err != nil {
		_ = left.Close()
		_ = right.Close()
		return nil, err
	}
	rightFields, err := e.registerNetConn(right, "pipe", rightHandle, map[string]any{"index": 1, "peer_index": 0}, nil)
	if err != nil {
		_ = right.Close()
		_ = e.closeNetConn(leftFields["handle"].(string))
		return nil, err
	}
	return map[string]any{"ok": true, "handles": []string{leftFields["handle"].(string), rightFields["handle"].(string)}, "conns": []string{leftFields["handle"].(string), rightFields["handle"].(string)}, "left": leftFields, "right": rightFields}, nil
}

func (e *scriptEnv) scriptNetResolveTCPAddr(value goja.Value) (any, error) {
	return e.resolveNetAddr(value, "tcp", func(network, address string) (stdnet.Addr, error) { return stdnet.ResolveTCPAddr(network, address) })
}

func (e *scriptEnv) scriptNetResolveUDPAddr(value goja.Value) (any, error) {
	return e.resolveNetAddr(value, "udp", func(network, address string) (stdnet.Addr, error) { return stdnet.ResolveUDPAddr(network, address) })
}

func (e *scriptEnv) scriptNetResolveIPAddr(value goja.Value) (any, error) {
	return e.resolveNetAddr(value, "ip", func(network, address string) (stdnet.Addr, error) { return stdnet.ResolveIPAddr(network, address) })
}

func (e *scriptEnv) scriptNetResolveUnixAddr(value goja.Value) (any, error) {
	return e.resolveNetAddr(value, "unix", func(network, address string) (stdnet.Addr, error) { return stdnet.ResolveUnixAddr(network, address) })
}

func (e *scriptEnv) resolveNetAddr(value goja.Value, fallbackNetwork string, fn func(string, string) (stdnet.Addr, error)) (any, error) {
	var args struct {
		Network string `json:"network"`
		Address string `json:"address"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	network := defaultNetwork(args.Network, fallbackNetwork)
	if strings.TrimSpace(args.Address) == "" {
		return nil, errors.New("address is required")
	}
	addr, err := fn(network, args.Address)
	fields := map[string]any{"network": network, "address": args.Address}
	if err == nil {
		fields["addr"] = netAddrInfo(addr)
	}
	return scriptGoResult(fields, err)
}

func (e *scriptEnv) scriptNetLookupHost(value goja.Value) (any, error) {
	var args struct {
		Host      string `json:"host"`
		TimeoutMS Uint32 `json:"timeout_ms"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Host == "" {
		return nil, errors.New("host is required")
	}
	ctx, cancel := e.contextWithTimeout(args.TimeoutMS)
	defer cancel()
	addrs, err := stdnet.DefaultResolver.LookupHost(ctx, args.Host)
	return scriptGoResult(map[string]any{"host": args.Host, "addrs": addrs}, err)
}

func (e *scriptEnv) scriptNetLookupIP(value goja.Value) (any, error) {
	var args struct {
		Network   string `json:"network"`
		Host      string `json:"host"`
		TimeoutMS Uint32 `json:"timeout_ms"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Host == "" {
		return nil, errors.New("host is required")
	}
	network := defaultNetwork(args.Network, "ip")
	ctx, cancel := e.contextWithTimeout(args.TimeoutMS)
	defer cancel()
	ips, err := stdnet.DefaultResolver.LookupIP(ctx, network, args.Host)
	infos := make([]map[string]any, 0, len(ips))
	stringsOut := make([]string, 0, len(ips))
	for _, ip := range ips {
		infos = append(infos, ipInfo(ip))
		stringsOut = append(stringsOut, ip.String())
	}
	return scriptGoResult(map[string]any{"network": network, "host": args.Host, "ips": infos, "addrs": stringsOut}, err)
}

func (e *scriptEnv) scriptNetLookupPort(value goja.Value) (any, error) {
	var args struct {
		Network   string `json:"network"`
		Service   string `json:"service"`
		TimeoutMS Uint32 `json:"timeout_ms"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Service == "" {
		return nil, errors.New("service is required")
	}
	network := defaultNetwork(args.Network, "tcp")
	ctx, cancel := e.contextWithTimeout(args.TimeoutMS)
	defer cancel()
	port, err := stdnet.DefaultResolver.LookupPort(ctx, network, args.Service)
	return scriptGoResult(map[string]any{"network": network, "service": args.Service, "port": port}, err)
}

func (e *scriptEnv) scriptNetLookupCNAME(value goja.Value) (any, error) {
	var args struct {
		Host      string `json:"host"`
		TimeoutMS Uint32 `json:"timeout_ms"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Host == "" {
		return nil, errors.New("host is required")
	}
	ctx, cancel := e.contextWithTimeout(args.TimeoutMS)
	defer cancel()
	cname, err := stdnet.DefaultResolver.LookupCNAME(ctx, args.Host)
	return scriptGoResult(map[string]any{"host": args.Host, "cname": cname}, err)
}

func (e *scriptEnv) scriptNetLookupAddr(value goja.Value) (any, error) {
	var args struct {
		Addr      string `json:"addr"`
		Address   string `json:"address"`
		TimeoutMS Uint32 `json:"timeout_ms"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	addr := args.Addr
	if addr == "" {
		addr = args.Address
	}
	if addr == "" {
		return nil, errors.New("addr or address is required")
	}
	ctx, cancel := e.contextWithTimeout(args.TimeoutMS)
	defer cancel()
	names, err := stdnet.DefaultResolver.LookupAddr(ctx, addr)
	return scriptGoResult(map[string]any{"addr": addr, "names": names}, err)
}

func (e *scriptEnv) scriptNetLookupMX(value goja.Value) (any, error) {
	var args struct {
		Name      string `json:"name"`
		TimeoutMS Uint32 `json:"timeout_ms"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Name == "" {
		return nil, errors.New("name is required")
	}
	ctx, cancel := e.contextWithTimeout(args.TimeoutMS)
	defer cancel()
	records, err := stdnet.DefaultResolver.LookupMX(ctx, args.Name)
	result := make([]map[string]any, 0, len(records))
	for _, record := range records {
		result = append(result, map[string]any{"host": record.Host, "pref": record.Pref})
	}
	return scriptGoResult(map[string]any{"name": args.Name, "records": result}, err)
}

func (e *scriptEnv) scriptNetLookupNS(value goja.Value) (any, error) {
	var args struct {
		Name      string `json:"name"`
		TimeoutMS Uint32 `json:"timeout_ms"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Name == "" {
		return nil, errors.New("name is required")
	}
	ctx, cancel := e.contextWithTimeout(args.TimeoutMS)
	defer cancel()
	records, err := stdnet.DefaultResolver.LookupNS(ctx, args.Name)
	result := make([]map[string]any, 0, len(records))
	for _, record := range records {
		result = append(result, map[string]any{"host": record.Host})
	}
	return scriptGoResult(map[string]any{"name": args.Name, "records": result}, err)
}

func (e *scriptEnv) scriptNetLookupTXT(value goja.Value) (any, error) {
	var args struct {
		Name      string `json:"name"`
		TimeoutMS Uint32 `json:"timeout_ms"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Name == "" {
		return nil, errors.New("name is required")
	}
	ctx, cancel := e.contextWithTimeout(args.TimeoutMS)
	defer cancel()
	records, err := stdnet.DefaultResolver.LookupTXT(ctx, args.Name)
	return scriptGoResult(map[string]any{"name": args.Name, "records": records}, err)
}

func (e *scriptEnv) scriptNetLookupSRV(value goja.Value) (any, error) {
	var args struct {
		Service   string `json:"service"`
		Proto     string `json:"proto"`
		Name      string `json:"name"`
		TimeoutMS Uint32 `json:"timeout_ms"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Name == "" {
		return nil, errors.New("name is required")
	}
	ctx, cancel := e.contextWithTimeout(args.TimeoutMS)
	defer cancel()
	cname, records, err := stdnet.DefaultResolver.LookupSRV(ctx, args.Service, args.Proto, args.Name)
	result := make([]map[string]any, 0, len(records))
	for _, record := range records {
		result = append(result, map[string]any{"target": record.Target, "port": record.Port, "priority": record.Priority, "weight": record.Weight})
	}
	return scriptGoResult(map[string]any{"service": args.Service, "proto": args.Proto, "name": args.Name, "cname": cname, "records": result}, err)
}

func (e *scriptEnv) scriptNetSplitHostPort(value goja.Value) (any, error) {
	var args struct {
		Address string `json:"address"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	host, port, err := stdnet.SplitHostPort(args.Address)
	return scriptGoResult(map[string]any{"address": args.Address, "host": host, "port": port}, err)
}

func (e *scriptEnv) scriptNetJoinHostPort(value goja.Value) (any, error) {
	var args struct {
		Host string `json:"host"`
		Port any    `json:"port"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	port := stringFromScriptValue(args.Port)
	if port == "" {
		return nil, errors.New("port is required")
	}
	address := stdnet.JoinHostPort(args.Host, port)
	return map[string]any{"ok": true, "host": args.Host, "port": port, "address": address}, nil
}

func (e *scriptEnv) scriptNetParseIP(value goja.Value) (any, error) {
	var args struct {
		IP string `json:"ip"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	ip := stdnet.ParseIP(args.IP)
	fields := map[string]any{"ok": true, "input": args.IP, "valid": ip != nil}
	if ip != nil {
		fields["ip"] = ipInfo(ip)
	}
	return fields, nil
}

func (e *scriptEnv) scriptNetParseCIDR(value goja.Value) (any, error) {
	var args struct {
		CIDR string `json:"cidr"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	ip, network, err := stdnet.ParseCIDR(args.CIDR)
	fields := map[string]any{"cidr": args.CIDR}
	if err == nil {
		fields["ip"] = ipInfo(ip)
		fields["network"] = netAddrInfo(network)
	}
	return scriptGoResult(fields, err)
}

func (e *scriptEnv) scriptNetInterfaceAddrs(value goja.Value) (any, error) {
	addrs, err := stdnet.InterfaceAddrs()
	infos := make([]map[string]any, 0, len(addrs))
	for _, addr := range addrs {
		infos = append(infos, netAddrInfo(addr))
	}
	return scriptGoResult(map[string]any{"addrs": infos}, err)
}

func (e *scriptEnv) scriptNetInterfaces(value goja.Value) (any, error) {
	interfaces, err := stdnet.Interfaces()
	infos := make([]map[string]any, 0, len(interfaces))
	for _, iface := range interfaces {
		infos = append(infos, netInterfaceInfo(iface))
	}
	return scriptGoResult(map[string]any{"interfaces": infos}, err)
}

func (e *scriptEnv) scriptNetInterfaceByName(value goja.Value) (any, error) {
	var args struct {
		Name string `json:"name"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	iface, err := stdnet.InterfaceByName(args.Name)
	fields := map[string]any{"name": args.Name}
	if err == nil && iface != nil {
		fields["interface"] = netInterfaceInfo(*iface)
	}
	return scriptGoResult(fields, err)
}

func (e *scriptEnv) scriptNetInterfaceByIndex(value goja.Value) (any, error) {
	var args struct {
		Index int `json:"index"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	iface, err := stdnet.InterfaceByIndex(args.Index)
	fields := map[string]any{"index": args.Index}
	if err == nil && iface != nil {
		fields["interface"] = netInterfaceInfo(*iface)
	}
	return scriptGoResult(fields, err)
}

func (e *scriptEnv) scriptNetConnRead(value goja.Value) (any, error) {
	var args struct {
		scriptNetConnRef
		Length    Uint64 `json:"length"`
		Encoding  string `json:"encoding"`
		TimeoutMS Uint32 `json:"timeout_ms"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Length > Uint64(e.app.config.MaxReadBytes) {
		return nil, fmt.Errorf("length %d exceeds max_read_bytes %d", args.Length, e.app.config.MaxReadBytes)
	}
	entry, err := e.resolveNetConn(args.scriptNetConnRef)
	if err != nil {
		return nil, err
	}
	fields := map[string]any{"conn": entry.Handle, "handle": entry.Handle}
	cleanup, err := temporaryNetDeadline(entry.Conn.SetReadDeadline, args.TimeoutMS)
	if err != nil {
		return scriptGoResult(fields, err)
	}
	defer cleanup()
	buf := make([]byte, int(args.Length))
	n, readErr := entry.Conn.Read(buf)
	fields["bytes_read"] = n
	if n > 0 || readErr == nil {
		encoded, err := encodeBytes(buf[:n], args.Encoding)
		if err != nil {
			return nil, err
		}
		for key, value := range encoded {
			fields[key] = value
		}
	}
	return scriptGoResult(fields, readErr)
}

func (e *scriptEnv) scriptNetConnWrite(value goja.Value) (any, error) {
	var args struct {
		scriptNetConnRef
		scriptDataInputArgs
		TimeoutMS Uint32 `json:"timeout_ms"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	data, err := e.scriptInputBytes(args.scriptDataInputArgs)
	if err != nil {
		return nil, err
	}
	entry, err := e.resolveNetConn(args.scriptNetConnRef)
	if err != nil {
		return nil, err
	}
	fields := map[string]any{"conn": entry.Handle, "handle": entry.Handle, "bytes_requested": len(data), "checksum64": checksum64(data)}
	cleanup, err := temporaryNetDeadline(entry.Conn.SetWriteDeadline, args.TimeoutMS)
	if err != nil {
		return scriptGoResult(fields, err)
	}
	defer cleanup()
	n, writeErr := entry.Conn.Write(data)
	fields["bytes_written"] = n
	return scriptGoResult(fields, writeErr)
}

func (e *scriptEnv) scriptNetConnClose(value goja.Value) (any, error) {
	var args scriptNetConnRef
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	handle := args.handle()
	if handle == "" {
		return nil, errors.New("conn or handle is required")
	}
	err := e.closeNetConn(handle)
	return scriptGoResult(map[string]any{"conn": handle, "handle": handle, "closed": err == nil}, err)
}

func (e *scriptEnv) scriptNetConnLocalAddr(value goja.Value) (any, error) {
	return e.scriptNetConnAddr(value, true)
}

func (e *scriptEnv) scriptNetConnRemoteAddr(value goja.Value) (any, error) {
	return e.scriptNetConnAddr(value, false)
}

func (e *scriptEnv) scriptNetConnAddr(value goja.Value, local bool) (any, error) {
	var args scriptNetConnRef
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.resolveNetConn(args)
	if err != nil {
		return nil, err
	}
	addr := entry.Conn.RemoteAddr()
	field := "remote_addr"
	if local {
		addr = entry.Conn.LocalAddr()
		field = "local_addr"
	}
	return map[string]any{"ok": true, "conn": entry.Handle, "handle": entry.Handle, field: netAddrInfo(addr), "addr": netAddrInfo(addr)}, nil
}

func (e *scriptEnv) scriptNetConnSetDeadline(value goja.Value) (any, error) {
	return e.scriptNetConnDeadline(value, "deadline")
}

func (e *scriptEnv) scriptNetConnSetReadDeadline(value goja.Value) (any, error) {
	return e.scriptNetConnDeadline(value, "read_deadline")
}

func (e *scriptEnv) scriptNetConnSetWriteDeadline(value goja.Value) (any, error) {
	return e.scriptNetConnDeadline(value, "write_deadline")
}

func (e *scriptEnv) scriptNetConnDeadline(value goja.Value, kind string) (any, error) {
	var args struct {
		scriptNetConnRef
		Time         string `json:"time"`
		Unix         *int64 `json:"unix"`
		UnixNano     *int64 `json:"unix_nano"`
		Deadline     string `json:"deadline"`
		DeadlineUnix *int64 `json:"deadline_unix"`
		DeadlineNano *int64 `json:"deadline_unix_nano"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	deadline, err := deadlineFromScriptArgs(args.Time, args.Unix, args.UnixNano, args.Deadline, args.DeadlineUnix, args.DeadlineNano)
	if err != nil {
		return nil, err
	}
	entry, err := e.resolveNetConn(args.scriptNetConnRef)
	if err != nil {
		return nil, err
	}
	switch kind {
	case "read_deadline":
		err = entry.Conn.SetReadDeadline(deadline)
	case "write_deadline":
		err = entry.Conn.SetWriteDeadline(deadline)
	default:
		err = entry.Conn.SetDeadline(deadline)
	}
	return scriptGoResult(map[string]any{"conn": entry.Handle, "handle": entry.Handle, "deadline": deadlineString(deadline)}, err)
}

func (e *scriptEnv) scriptNetTCPConnCloseRead(value goja.Value) (any, error) {
	tcp, entry, err := e.resolveTCPConnValue(value)
	if err != nil {
		return nil, err
	}
	err = tcp.CloseRead()
	return scriptGoResult(map[string]any{"conn": entry.Handle, "handle": entry.Handle}, err)
}

func (e *scriptEnv) scriptNetTCPConnCloseWrite(value goja.Value) (any, error) {
	tcp, entry, err := e.resolveTCPConnValue(value)
	if err != nil {
		return nil, err
	}
	err = tcp.CloseWrite()
	return scriptGoResult(map[string]any{"conn": entry.Handle, "handle": entry.Handle}, err)
}

func (e *scriptEnv) scriptNetTCPConnSetKeepAlive(value goja.Value) (any, error) {
	var args struct {
		scriptNetConnRef
		KeepAlive bool `json:"keep_alive"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	tcp, entry, err := e.resolveTCPConn(args.scriptNetConnRef)
	if err != nil {
		return nil, err
	}
	err = tcp.SetKeepAlive(args.KeepAlive)
	return scriptGoResult(map[string]any{"conn": entry.Handle, "handle": entry.Handle, "keep_alive": args.KeepAlive}, err)
}

func (e *scriptEnv) scriptNetTCPConnSetKeepAlivePeriod(value goja.Value) (any, error) {
	var args struct {
		scriptNetConnRef
		PeriodMS Uint64 `json:"period_ms"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	tcp, entry, err := e.resolveTCPConn(args.scriptNetConnRef)
	if err != nil {
		return nil, err
	}
	period := time.Duration(args.PeriodMS) * time.Millisecond
	err = tcp.SetKeepAlivePeriod(period)
	return scriptGoResult(map[string]any{"conn": entry.Handle, "handle": entry.Handle, "period_ms": uint64(args.PeriodMS)}, err)
}

func (e *scriptEnv) scriptNetTCPConnSetNoDelay(value goja.Value) (any, error) {
	var args struct {
		scriptNetConnRef
		NoDelay bool `json:"no_delay"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	tcp, entry, err := e.resolveTCPConn(args.scriptNetConnRef)
	if err != nil {
		return nil, err
	}
	err = tcp.SetNoDelay(args.NoDelay)
	return scriptGoResult(map[string]any{"conn": entry.Handle, "handle": entry.Handle, "no_delay": args.NoDelay}, err)
}

func (e *scriptEnv) scriptNetListenerAccept(value goja.Value) (any, error) {
	var args struct {
		scriptNetListenerRef
		Handle    string `json:"conn_handle"`
		Conn      string `json:"conn"`
		TimeoutMS Uint32 `json:"timeout_ms"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.resolveNetListener(args.scriptNetListenerRef)
	if err != nil {
		return nil, err
	}
	fields := map[string]any{"listener": entry.Handle, "handle": entry.Handle}
	cleanup, err := temporaryListenerDeadline(entry.Listener, args.TimeoutMS)
	if err != nil {
		return scriptGoResult(fields, err)
	}
	defer cleanup()
	conn, acceptErr := entry.Listener.Accept()
	connHandle := args.Handle
	if connHandle == "" {
		connHandle = args.Conn
	}
	return e.registerNetConn(conn, connNetwork(conn), connHandle, fields, acceptErr)
}

func (e *scriptEnv) scriptNetListenerClose(value goja.Value) (any, error) {
	var args scriptNetListenerRef
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	handle := args.handle()
	if handle == "" {
		return nil, errors.New("listener or handle is required")
	}
	err := e.closeNetListener(handle)
	return scriptGoResult(map[string]any{"listener": handle, "handle": handle, "closed": err == nil}, err)
}

func (e *scriptEnv) scriptNetListenerAddr(value goja.Value) (any, error) {
	var args scriptNetListenerRef
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.resolveNetListener(args)
	if err != nil {
		return nil, err
	}
	addr := netAddrInfo(entry.Listener.Addr())
	return map[string]any{"ok": true, "listener": entry.Handle, "handle": entry.Handle, "addr": addr, "local_addr": addr}, nil
}

func (e *scriptEnv) scriptNetListenerSetDeadline(value goja.Value) (any, error) {
	var args struct {
		scriptNetListenerRef
		Time         string `json:"time"`
		Unix         *int64 `json:"unix"`
		UnixNano     *int64 `json:"unix_nano"`
		Deadline     string `json:"deadline"`
		DeadlineUnix *int64 `json:"deadline_unix"`
		DeadlineNano *int64 `json:"deadline_unix_nano"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	deadline, err := deadlineFromScriptArgs(args.Time, args.Unix, args.UnixNano, args.Deadline, args.DeadlineUnix, args.DeadlineNano)
	if err != nil {
		return nil, err
	}
	entry, err := e.resolveNetListener(args.scriptNetListenerRef)
	if err != nil {
		return nil, err
	}
	err = setListenerDeadline(entry.Listener, deadline)
	return scriptGoResult(map[string]any{"listener": entry.Handle, "handle": entry.Handle, "deadline": deadlineString(deadline)}, err)
}

func (e *scriptEnv) scriptNetPacketReadFrom(value goja.Value) (any, error) {
	var args struct {
		scriptNetPacketConnRef
		Length    Uint64 `json:"length"`
		Encoding  string `json:"encoding"`
		TimeoutMS Uint32 `json:"timeout_ms"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Length > Uint64(e.app.config.MaxReadBytes) {
		return nil, fmt.Errorf("length %d exceeds max_read_bytes %d", args.Length, e.app.config.MaxReadBytes)
	}
	entry, err := e.resolveNetPacketConn(args.scriptNetPacketConnRef)
	if err != nil {
		return nil, err
	}
	fields := map[string]any{"packet": entry.Handle, "handle": entry.Handle}
	cleanup, err := temporaryNetDeadline(entry.PacketConn.SetReadDeadline, args.TimeoutMS)
	if err != nil {
		return scriptGoResult(fields, err)
	}
	defer cleanup()
	buf := make([]byte, int(args.Length))
	n, addr, readErr := entry.PacketConn.ReadFrom(buf)
	fields["bytes_read"] = n
	fields["addr"] = netAddrInfo(addr)
	fields["remote_addr"] = netAddrInfo(addr)
	if n > 0 || readErr == nil {
		encoded, err := encodeBytes(buf[:n], args.Encoding)
		if err != nil {
			return nil, err
		}
		for key, value := range encoded {
			fields[key] = value
		}
	}
	return scriptGoResult(fields, readErr)
}

func (e *scriptEnv) scriptNetPacketWriteTo(value goja.Value) (any, error) {
	var args struct {
		scriptNetPacketConnRef
		scriptDataInputArgs
		Network   string `json:"network"`
		Address   string `json:"address"`
		TimeoutMS Uint32 `json:"timeout_ms"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if strings.TrimSpace(args.Address) == "" {
		return nil, errors.New("address is required")
	}
	entry, err := e.resolveNetPacketConn(args.scriptNetPacketConnRef)
	if err != nil {
		return nil, err
	}
	network := defaultNetwork(args.Network, entry.Network)
	addr, err := resolveNetAddrForNetwork(network, args.Address)
	if err != nil {
		return nil, err
	}
	data, err := e.scriptInputBytes(args.scriptDataInputArgs)
	if err != nil {
		return nil, err
	}
	fields := map[string]any{"packet": entry.Handle, "handle": entry.Handle, "network": network, "address": args.Address, "addr": netAddrInfo(addr), "bytes_requested": len(data), "checksum64": checksum64(data)}
	cleanup, err := temporaryNetDeadline(entry.PacketConn.SetWriteDeadline, args.TimeoutMS)
	if err != nil {
		return scriptGoResult(fields, err)
	}
	defer cleanup()
	n, writeErr := entry.PacketConn.WriteTo(data, addr)
	fields["bytes_written"] = n
	return scriptGoResult(fields, writeErr)
}

func (e *scriptEnv) scriptNetPacketClose(value goja.Value) (any, error) {
	var args scriptNetPacketConnRef
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	handle := args.handle()
	if handle == "" {
		return nil, errors.New("packet or handle is required")
	}
	err := e.closeNetPacketConn(handle)
	return scriptGoResult(map[string]any{"packet": handle, "handle": handle, "closed": err == nil}, err)
}

func (e *scriptEnv) scriptNetPacketLocalAddr(value goja.Value) (any, error) {
	var args scriptNetPacketConnRef
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.resolveNetPacketConn(args)
	if err != nil {
		return nil, err
	}
	addr := netAddrInfo(entry.PacketConn.LocalAddr())
	return map[string]any{"ok": true, "packet": entry.Handle, "handle": entry.Handle, "addr": addr, "local_addr": addr}, nil
}

func (e *scriptEnv) scriptNetPacketSetDeadline(value goja.Value) (any, error) {
	return e.scriptNetPacketDeadline(value, "deadline")
}

func (e *scriptEnv) scriptNetPacketSetReadDeadline(value goja.Value) (any, error) {
	return e.scriptNetPacketDeadline(value, "read_deadline")
}

func (e *scriptEnv) scriptNetPacketSetWriteDeadline(value goja.Value) (any, error) {
	return e.scriptNetPacketDeadline(value, "write_deadline")
}

func (e *scriptEnv) scriptNetPacketDeadline(value goja.Value, kind string) (any, error) {
	var args struct {
		scriptNetPacketConnRef
		Time         string `json:"time"`
		Unix         *int64 `json:"unix"`
		UnixNano     *int64 `json:"unix_nano"`
		Deadline     string `json:"deadline"`
		DeadlineUnix *int64 `json:"deadline_unix"`
		DeadlineNano *int64 `json:"deadline_unix_nano"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	deadline, err := deadlineFromScriptArgs(args.Time, args.Unix, args.UnixNano, args.Deadline, args.DeadlineUnix, args.DeadlineNano)
	if err != nil {
		return nil, err
	}
	entry, err := e.resolveNetPacketConn(args.scriptNetPacketConnRef)
	if err != nil {
		return nil, err
	}
	switch kind {
	case "read_deadline":
		err = entry.PacketConn.SetReadDeadline(deadline)
	case "write_deadline":
		err = entry.PacketConn.SetWriteDeadline(deadline)
	default:
		err = entry.PacketConn.SetDeadline(deadline)
	}
	return scriptGoResult(map[string]any{"packet": entry.Handle, "handle": entry.Handle, "deadline": deadlineString(deadline)}, err)
}

func (e *scriptEnv) contextWithTimeout(timeoutMS Uint32) (context.Context, context.CancelFunc) {
	if timeoutMS == 0 {
		return e.ctx, func() {}
	}
	return context.WithTimeout(e.ctx, timeoutDuration(timeoutMS))
}

func timeoutDuration(timeoutMS Uint32) time.Duration {
	return time.Duration(uint32(timeoutMS)) * time.Millisecond
}

func defaultNetwork(network, fallback string) string {
	network = strings.TrimSpace(network)
	if network == "" {
		return fallback
	}
	return network
}

func stringFromScriptValue(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32)
	case int:
		return strconv.Itoa(v)
	case int8:
		return strconv.FormatInt(int64(v), 10)
	case int16:
		return strconv.FormatInt(int64(v), 10)
	case int32:
		return strconv.FormatInt(int64(v), 10)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint:
		return strconv.FormatUint(uint64(v), 10)
	case uint8:
		return strconv.FormatUint(uint64(v), 10)
	case uint16:
		return strconv.FormatUint(uint64(v), 10)
	case uint32:
		return strconv.FormatUint(uint64(v), 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	default:
		return fmt.Sprint(v)
	}
}

func deadlineFromScriptArgs(text string, unixSeconds *int64, unixNano *int64, fallbackText string, fallbackUnix *int64, fallbackNano *int64) (time.Time, error) {
	if text == "" && fallbackText != "" {
		text = fallbackText
	}
	if unixSeconds == nil && fallbackUnix != nil {
		unixSeconds = fallbackUnix
	}
	if unixNano == nil && fallbackNano != nil {
		unixNano = fallbackNano
	}
	return parseOptionalDeadline(text, unixSeconds, unixNano, "deadline")
}

func deadlineString(deadline time.Time) string {
	if deadline.IsZero() {
		return ""
	}
	return deadline.Format(time.RFC3339Nano)
}

func temporaryNetDeadline(set func(time.Time) error, timeoutMS Uint32) (func(), error) {
	if timeoutMS == 0 {
		return func() {}, nil
	}
	if err := set(time.Now().Add(timeoutDuration(timeoutMS))); err != nil {
		return nil, err
	}
	return func() { _ = set(time.Time{}) }, nil
}

type listenerDeadlineSetter interface {
	SetDeadline(time.Time) error
}

func temporaryListenerDeadline(listener stdnet.Listener, timeoutMS Uint32) (func(), error) {
	if timeoutMS == 0 {
		return func() {}, nil
	}
	setter, ok := listener.(listenerDeadlineSetter)
	if !ok {
		return nil, errors.New("listener does not support deadlines")
	}
	return temporaryNetDeadline(setter.SetDeadline, timeoutMS)
}

func setListenerDeadline(listener stdnet.Listener, deadline time.Time) error {
	setter, ok := listener.(listenerDeadlineSetter)
	if !ok {
		return errors.New("listener does not support deadlines")
	}
	return setter.SetDeadline(deadline)
}

func resolveNetAddrForNetwork(network, address string) (stdnet.Addr, error) {
	switch {
	case strings.HasPrefix(network, "tcp"):
		return stdnet.ResolveTCPAddr(network, address)
	case strings.HasPrefix(network, "udp"):
		return stdnet.ResolveUDPAddr(network, address)
	case strings.HasPrefix(network, "unix"):
		return stdnet.ResolveUnixAddr(network, address)
	case strings.HasPrefix(network, "ip"):
		return stdnet.ResolveIPAddr(network, address)
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}
}

func connNetwork(conn stdnet.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	return conn.RemoteAddr().Network()
}

func (e *scriptEnv) registerNetConn(conn stdnet.Conn, network, requestedHandle string, fields map[string]any, err error) (map[string]any, error) {
	if fields == nil {
		fields = map[string]any{}
	}
	if err != nil {
		return scriptGoResult(fields, err)
	}
	if conn == nil {
		return nil, errors.New("net connection is nil")
	}
	e.app.mu.Lock()
	defer e.app.mu.Unlock()
	if requestedHandle != "" {
		if err := validateName("net connection handle", requestedHandle); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if _, exists := e.app.netConns[requestedHandle]; exists {
			_ = conn.Close()
			return nil, fmt.Errorf("net connection handle %q already exists", requestedHandle)
		}
	} else {
		for {
			e.app.nextNetConnHandle++
			requestedHandle = fmt.Sprintf("conn%d", e.app.nextNetConnHandle)
			if _, exists := e.app.netConns[requestedHandle]; !exists {
				break
			}
		}
	}
	if network == "" {
		network = connNetwork(conn)
	}
	entry := &netConnEntry{Handle: requestedHandle, Network: network, Conn: conn}
	e.app.netConns[requestedHandle] = entry
	for key, value := range netConnInfo(entry) {
		fields[key] = value
	}
	return scriptGoResult(fields, nil)
}

func (e *scriptEnv) registerNetListener(listener stdnet.Listener, network, requestedHandle string, fields map[string]any, err error) (map[string]any, error) {
	if fields == nil {
		fields = map[string]any{}
	}
	if err != nil {
		return scriptGoResult(fields, err)
	}
	if listener == nil {
		return nil, errors.New("net listener is nil")
	}
	e.app.mu.Lock()
	defer e.app.mu.Unlock()
	if requestedHandle != "" {
		if err := validateName("net listener handle", requestedHandle); err != nil {
			_ = listener.Close()
			return nil, err
		}
		if _, exists := e.app.netListeners[requestedHandle]; exists {
			_ = listener.Close()
			return nil, fmt.Errorf("net listener handle %q already exists", requestedHandle)
		}
	} else {
		for {
			e.app.nextNetListenerHandle++
			requestedHandle = fmt.Sprintf("listener%d", e.app.nextNetListenerHandle)
			if _, exists := e.app.netListeners[requestedHandle]; !exists {
				break
			}
		}
	}
	if network == "" && listener.Addr() != nil {
		network = listener.Addr().Network()
	}
	entry := &netListenerEntry{Handle: requestedHandle, Network: network, Listener: listener}
	e.app.netListeners[requestedHandle] = entry
	for key, value := range netListenerInfo(entry) {
		fields[key] = value
	}
	return scriptGoResult(fields, nil)
}

func (e *scriptEnv) registerNetPacketConn(packet stdnet.PacketConn, network, requestedHandle string, fields map[string]any, err error) (map[string]any, error) {
	if fields == nil {
		fields = map[string]any{}
	}
	if err != nil {
		return scriptGoResult(fields, err)
	}
	if packet == nil {
		return nil, errors.New("net packet connection is nil")
	}
	e.app.mu.Lock()
	defer e.app.mu.Unlock()
	if requestedHandle != "" {
		if err := validateName("net packet connection handle", requestedHandle); err != nil {
			_ = packet.Close()
			return nil, err
		}
		if _, exists := e.app.netPacketConns[requestedHandle]; exists {
			_ = packet.Close()
			return nil, fmt.Errorf("net packet connection handle %q already exists", requestedHandle)
		}
	} else {
		for {
			e.app.nextNetPacketHandle++
			requestedHandle = fmt.Sprintf("packet%d", e.app.nextNetPacketHandle)
			if _, exists := e.app.netPacketConns[requestedHandle]; !exists {
				break
			}
		}
	}
	if network == "" && packet.LocalAddr() != nil {
		network = packet.LocalAddr().Network()
	}
	entry := &netPacketConnEntry{Handle: requestedHandle, Network: network, PacketConn: packet}
	e.app.netPacketConns[requestedHandle] = entry
	for key, value := range netPacketConnInfo(entry) {
		fields[key] = value
	}
	return scriptGoResult(fields, nil)
}

func (e *scriptEnv) resolveNetConn(ref scriptNetConnRef) (*netConnEntry, error) {
	handle := ref.handle()
	if handle == "" {
		return nil, errors.New("conn or handle is required")
	}
	e.app.mu.Lock()
	defer e.app.mu.Unlock()
	entry, ok := e.app.netConns[handle]
	if !ok {
		return nil, fmt.Errorf("net connection handle %q not found", handle)
	}
	return entry, nil
}

func (e *scriptEnv) resolveNetListener(ref scriptNetListenerRef) (*netListenerEntry, error) {
	handle := ref.handle()
	if handle == "" {
		return nil, errors.New("listener or handle is required")
	}
	e.app.mu.Lock()
	defer e.app.mu.Unlock()
	entry, ok := e.app.netListeners[handle]
	if !ok {
		return nil, fmt.Errorf("net listener handle %q not found", handle)
	}
	return entry, nil
}

func (e *scriptEnv) resolveNetPacketConn(ref scriptNetPacketConnRef) (*netPacketConnEntry, error) {
	handle := ref.handle()
	if handle == "" {
		return nil, errors.New("packet or handle is required")
	}
	e.app.mu.Lock()
	defer e.app.mu.Unlock()
	entry, ok := e.app.netPacketConns[handle]
	if !ok {
		return nil, fmt.Errorf("net packet connection handle %q not found", handle)
	}
	return entry, nil
}

func (e *scriptEnv) closeNetConn(handle string) error {
	e.app.mu.Lock()
	entry, ok := e.app.netConns[handle]
	e.app.mu.Unlock()
	if !ok {
		return fmt.Errorf("net connection handle %q not found", handle)
	}
	err := entry.Conn.Close()
	if err == nil {
		e.app.mu.Lock()
		if e.app.netConns[handle] == entry {
			delete(e.app.netConns, handle)
		}
		e.app.mu.Unlock()
	}
	return err
}

func (e *scriptEnv) closeNetListener(handle string) error {
	e.app.mu.Lock()
	entry, ok := e.app.netListeners[handle]
	e.app.mu.Unlock()
	if !ok {
		return fmt.Errorf("net listener handle %q not found", handle)
	}
	err := entry.Listener.Close()
	if err == nil {
		e.app.mu.Lock()
		if e.app.netListeners[handle] == entry {
			delete(e.app.netListeners, handle)
		}
		e.app.mu.Unlock()
	}
	return err
}

func (e *scriptEnv) closeNetPacketConn(handle string) error {
	e.app.mu.Lock()
	entry, ok := e.app.netPacketConns[handle]
	e.app.mu.Unlock()
	if !ok {
		return fmt.Errorf("net packet connection handle %q not found", handle)
	}
	err := entry.PacketConn.Close()
	if err == nil {
		e.app.mu.Lock()
		if e.app.netPacketConns[handle] == entry {
			delete(e.app.netPacketConns, handle)
		}
		e.app.mu.Unlock()
	}
	return err
}

func (e *scriptEnv) resolveTCPConnValue(value goja.Value) (*stdnet.TCPConn, *netConnEntry, error) {
	var args scriptNetConnRef
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, nil, err
	}
	return e.resolveTCPConn(args)
}

func (e *scriptEnv) resolveTCPConn(ref scriptNetConnRef) (*stdnet.TCPConn, *netConnEntry, error) {
	entry, err := e.resolveNetConn(ref)
	if err != nil {
		return nil, nil, err
	}
	tcp, ok := entry.Conn.(*stdnet.TCPConn)
	if !ok {
		return nil, entry, fmt.Errorf("net connection %q is %T, not *net.TCPConn", entry.Handle, entry.Conn)
	}
	return tcp, entry, nil
}

func netConnInfo(entry *netConnEntry) map[string]any {
	fields := map[string]any{"handle": entry.Handle, "conn": entry.Handle, "network": entry.Network}
	if entry.Conn != nil {
		fields["local_addr"] = netAddrInfo(entry.Conn.LocalAddr())
		fields["remote_addr"] = netAddrInfo(entry.Conn.RemoteAddr())
	}
	return fields
}

func netListenerInfo(entry *netListenerEntry) map[string]any {
	fields := map[string]any{"handle": entry.Handle, "listener": entry.Handle, "network": entry.Network}
	if entry.Listener != nil {
		fields["addr"] = netAddrInfo(entry.Listener.Addr())
		fields["local_addr"] = netAddrInfo(entry.Listener.Addr())
	}
	return fields
}

func netPacketConnInfo(entry *netPacketConnEntry) map[string]any {
	fields := map[string]any{"handle": entry.Handle, "packet": entry.Handle, "network": entry.Network}
	if entry.PacketConn != nil {
		fields["addr"] = netAddrInfo(entry.PacketConn.LocalAddr())
		fields["local_addr"] = netAddrInfo(entry.PacketConn.LocalAddr())
	}
	return fields
}

func netConnInfosLocked(entries map[string]*netConnEntry) []map[string]any {
	infos := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		infos = append(infos, netConnInfo(entry))
	}
	sort.Slice(infos, func(i, j int) bool { return fmt.Sprint(infos[i]["handle"]) < fmt.Sprint(infos[j]["handle"]) })
	return infos
}

func netListenerInfosLocked(entries map[string]*netListenerEntry) []map[string]any {
	infos := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		infos = append(infos, netListenerInfo(entry))
	}
	sort.Slice(infos, func(i, j int) bool { return fmt.Sprint(infos[i]["handle"]) < fmt.Sprint(infos[j]["handle"]) })
	return infos
}

func netPacketConnInfosLocked(entries map[string]*netPacketConnEntry) []map[string]any {
	infos := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		infos = append(infos, netPacketConnInfo(entry))
	}
	sort.Slice(infos, func(i, j int) bool { return fmt.Sprint(infos[i]["handle"]) < fmt.Sprint(infos[j]["handle"]) })
	return infos
}

func netAddrInfo(addr stdnet.Addr) map[string]any {
	if addr == nil {
		return nil
	}
	fields := map[string]any{"network": addr.Network(), "address": addr.String()}
	switch typed := addr.(type) {
	case *stdnet.TCPAddr:
		fields["ip"] = typed.IP.String()
		fields["port"] = typed.Port
		fields["zone"] = typed.Zone
		fields["ip_info"] = ipInfo(typed.IP)
	case *stdnet.UDPAddr:
		fields["ip"] = typed.IP.String()
		fields["port"] = typed.Port
		fields["zone"] = typed.Zone
		fields["ip_info"] = ipInfo(typed.IP)
	case *stdnet.IPAddr:
		fields["ip"] = typed.IP.String()
		fields["zone"] = typed.Zone
		fields["ip_info"] = ipInfo(typed.IP)
	case *stdnet.UnixAddr:
		fields["name"] = typed.Name
		fields["net"] = typed.Net
	case *stdnet.IPNet:
		fields["ip"] = typed.IP.String()
		fields["mask_hex"] = hex.EncodeToString(typed.Mask)
		ones, bits := typed.Mask.Size()
		fields["prefix_len"] = ones
		fields["bits"] = bits
		fields["ip_info"] = ipInfo(typed.IP)
	}
	return fields
}

func ipInfo(ip stdnet.IP) map[string]any {
	fields := map[string]any{"string": ip.String(), "bytes_hex": hex.EncodeToString([]byte(ip)), "is_ipv4": ip.To4() != nil, "is_ipv6": ip.To4() == nil && ip.To16() != nil}
	if ip4 := ip.To4(); ip4 != nil {
		fields["v4_hex"] = hex.EncodeToString([]byte(ip4))
	}
	if ip16 := ip.To16(); ip16 != nil {
		fields["v16_hex"] = hex.EncodeToString([]byte(ip16))
	}
	fields["is_unspecified"] = ip.IsUnspecified()
	fields["is_loopback"] = ip.IsLoopback()
	fields["is_private"] = ip.IsPrivate()
	fields["is_multicast"] = ip.IsMulticast()
	fields["is_link_local_unicast"] = ip.IsLinkLocalUnicast()
	fields["is_global_unicast"] = ip.IsGlobalUnicast()
	return fields
}

func netInterfaceInfo(iface stdnet.Interface) map[string]any {
	fields := map[string]any{"index": iface.Index, "mtu": iface.MTU, "name": iface.Name, "hardware_addr": iface.HardwareAddr.String(), "flags": iface.Flags.String()}
	addrs, err := iface.Addrs()
	if err == nil {
		infos := make([]map[string]any, 0, len(addrs))
		for _, addr := range addrs {
			infos = append(infos, netAddrInfo(addr))
		}
		fields["addrs"] = infos
	} else {
		fields["addrs_error"] = err.Error()
	}
	multicastAddrs, err := iface.MulticastAddrs()
	if err == nil {
		infos := make([]map[string]any, 0, len(multicastAddrs))
		for _, addr := range multicastAddrs {
			infos = append(infos, netAddrInfo(addr))
		}
		fields["multicast_addrs"] = infos
	} else {
		fields["multicast_addrs_error"] = err.Error()
	}
	return fields
}

func netReaderFromConn(e *scriptEnv, connHandle string) (stdio.Reader, func(), error) {
	entry, err := e.resolveNetConn(scriptNetConnRef{Conn: connHandle})
	if err != nil {
		return nil, nil, err
	}
	return entry.Conn, func() {}, nil
}

func netWriterFromConn(e *scriptEnv, connHandle string) (stdio.Writer, func(), error) {
	entry, err := e.resolveNetConn(scriptNetConnRef{Conn: connHandle})
	if err != nil {
		return nil, nil, err
	}
	return entry.Conn, func() {}, nil
}
