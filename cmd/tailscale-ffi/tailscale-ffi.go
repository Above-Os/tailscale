//go:build windows && cgo

/*
  set GOOS=windows
  set GOARCH=amd64
  set CGO_ENABLED=1
  go build -v -buildmode=c-shared -ldflags="-s -w" -o tailscale-ffi.dll ./cmd/tailscale-ffi
*/

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unsafe"

	"tailscale.com/client/local"
	cli "tailscale.com/cmd/tailscale/cli"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/portmapper"
	"tailscale.com/paths"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

/*
#include <stdio.h>

// Inline C stubs for function pointers
typedef void (*Callback)();
static inline void call_out(Callback ptr, void *data) {
    (ptr)(data);
}
*/
import "C"

func main() {}

var localClient local.Client

func ffiLogf(format string, args ...any) {
	log.Printf("tailscale-ffi: "+format, args...)
}

func (k vpnJobKind) String() string {
	switch k {
	case vpnJobStart:
		return "start"
	case vpnJobLogout:
		return "logout"
	default:
		return "unknown"
	}
}

//export RunWithArgs
func RunWithArgs(argstr *C.char) *C.char {
	args := strings.Fields(C.GoString(argstr))
	if err := cli.Run(args); err != nil {
		ffiLogf("RunWithArgs: %v", err)
		return errorCString(err)
	}
	return errorCString(nil)
}

type vpnJobKind int

const (
	vpnJobStart vpnJobKind = iota
	vpnJobLogout
)

type vpnJob struct {
	kind        vpnJobKind
	loginServer string
	authKey     string
	acceptDNS   bool
	done        C.Callback
}

var (
	vpnJobs   []vpnJob
	vpnJobsMu sync.Mutex
	vpnNotify chan struct{}
)

func init() {
	vpnNotify = make(chan struct{}, 1)
	localClient.Socket = paths.DefaultTailscaledSocket()
	go vpnWorker()
}

func vpnWorker() {
	for range vpnNotify {
		for {
			job := vpnDequeue()
			if job == nil {
				break
			}
			ctx := context.Background()
			var err error
			switch job.kind {
			case vpnJobLogout:
				err = localClient.Logout(ctx)
			case vpnJobStart:
				err = startVpn(ctx, job.loginServer, job.authKey, job.acceptDNS)
			}
			if err != nil {
				ffiLogf("vpn %s: %v", job.kind, err)
			}
			if job.done != nil {
				C.call_out(job.done, unsafe.Pointer(errorCString(err)))
			}
		}
	}
}

func vpnEnqueue(job vpnJob) {
	vpnJobsMu.Lock()
	kept := make([]vpnJob, 0, len(vpnJobs))
	for _, j := range vpnJobs {
		if j.kind == vpnJobStart && (job.kind == vpnJobStart || job.kind == vpnJobLogout) {
			continue
		}
		kept = append(kept, j)
	}
	if job.kind == vpnJobLogout {
		vpnJobs = append([]vpnJob{job}, kept...)
	} else {
		vpnJobs = append(kept, job)
	}
	vpnJobsMu.Unlock()
	select {
	case vpnNotify <- struct{}{}:
	default:
	}
}

func vpnDequeue() *vpnJob {
	vpnJobsMu.Lock()
	defer vpnJobsMu.Unlock()
	if len(vpnJobs) == 0 {
		return nil
	}
	job := vpnJobs[0]
	vpnJobs = vpnJobs[1:]
	return &job
}

//export StartVpnAsync
func StartVpnAsync(loginServer *C.char, authKey *C.char, acceptDNS bool, done C.Callback) *C.char {
	vpnEnqueue(vpnJob{
		kind:        vpnJobStart,
		loginServer: C.GoString(loginServer),
		authKey:     C.GoString(authKey),
		acceptDNS:   acceptDNS,
		done:        done,
	})
	return errorCString(nil)
}

//export LogoutAsync
func LogoutAsync(done C.Callback) *C.char {
	vpnEnqueue(vpnJob{
		kind: vpnJobLogout,
		done: done,
	})
	return errorCString(nil)
}

func startVpn(ctx context.Context, loginServer, authKey string, acceptDNS bool) error {
	if _, err := localClient.Status(ctx); err != nil {
		return err
	}
	prefs := ipn.NewPrefs()
	prefs.ControlURL = loginServer
	prefs.WantRunning = true
	prefs.RouteAll = true
	prefs.CorpDNS = acceptDNS
	prefs.ShieldsUp = true
	prefs.ForceDaemon = true
	if err := localClient.CheckPrefs(ctx, prefs); err != nil {
		return err
	}
	if err := localClient.Start(ctx, ipn.Options{AuthKey: authKey, UpdatePrefs: prefs}); err != nil {
		return err
	}
	return localClient.StartLoginInteractive(ctx)
}

func errorCString(err error) *C.char {
	if err == nil {
		return C.CString("")
	}
	return C.CString(err.Error())
}

//export SetExitNode
func SetExitNode(ipStr *C.char) *C.char {
	ctx := context.Background()
	err := setExitNode(ctx, C.GoString(ipStr))
	return errorCString(err)
}

//export SetExitNodeAllowLANAccess
func SetExitNodeAllowLANAccess(allow bool) *C.char {
	ctx := context.Background()
	err := setExitNodeAllowLANAccess(ctx, allow)
	return errorCString(err)
}

func setExitNode(ctx context.Context, ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		mp := &ipn.MaskedPrefs{
			ExitNodeIPSet: true,
			ExitNodeIDSet: true,
		}
		_, err := localClient.EditPrefs(ctx, mp)
		return err
	}

	st, err := localClient.Status(ctx)
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}

	mp := &ipn.MaskedPrefs{
		ExitNodeIPSet: true,
		ExitNodeIDSet: true,
	}
	if expr, useAuto := ipn.ParseAutoExitNodeString(ip); useAuto {
		mp.AutoExitNode = expr
		mp.AutoExitNodeSet = true
	} else if err := mp.SetExitNodeIP(ip, st); err != nil {
		return err
	}
	return editPrefsChecked(ctx, mp)
}

func setExitNodeAllowLANAccess(ctx context.Context, allow bool) error {
	mp := &ipn.MaskedPrefs{
		ExitNodeAllowLANAccessSet: true,
		Prefs: ipn.Prefs{
			ExitNodeAllowLANAccess: allow,
		},
	}
	return editPrefsChecked(ctx, mp)
}

func editPrefsChecked(ctx context.Context, mp *ipn.MaskedPrefs) error {
	curPrefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return fmt.Errorf("get prefs: %w", err)
	}
	checkPrefs := curPrefs.Clone()
	checkPrefs.ApplyEdits(mp)
	if err := localClient.CheckPrefs(ctx, checkPrefs); err != nil {
		return err
	}
	_, err = localClient.EditPrefs(ctx, mp)
	return err
}

//export WatchIPN
func WatchIPN(initial bool, callback C.Callback) *C.char {
	go func() {
		var watchIPNArgs struct {
			netmap         bool
			initial        bool
			showPrivateKey bool
		}
		watchIPNArgs.netmap = true
		watchIPNArgs.initial = initial
		watchIPNArgs.showPrivateKey = false

		ctx := context.Background()

		var mask ipn.NotifyWatchOpt
		if watchIPNArgs.initial {
			mask = ipn.NotifyInitialState | ipn.NotifyInitialPrefs | ipn.NotifyInitialNetMap
		}
		if !watchIPNArgs.showPrivateKey {
			mask |= ipn.NotifyNoPrivateKeys
		}
		watcher, err := localClient.WatchIPNBus(ctx, mask)
		if err != nil {
			ffiLogf("WatchIPN: WatchIPNBus: %v", err)
			return
		}
		defer watcher.Close()
		ffiLogf("WatchIPN: connected (initial=%v)", initial)
		for {
			n, err := watcher.Next()
			if err != nil {
				ffiLogf("WatchIPN: Next: %v", err)
				j, _ := json.MarshalIndent(n, "", "\t")
				C.call_out(callback, unsafe.Pointer(C.CString(string(j))))
				return
			}
			if !watchIPNArgs.netmap {
				n.NetMap = nil
			}
			j, _ := json.MarshalIndent(n, "", "\t")
			C.call_out(callback, unsafe.Pointer(C.CString(string(j))))
			if initial {
				break
			}
		}
	}()
	return C.CString("")
}

//export SetCookie
func SetCookie(cookiestr *C.char) bool {
	cookie := C.GoString(cookiestr)
	ctx := context.Background()
	err := localClient.SetDevStoreKeyValue(ctx, "Cookie", cookie)
	if err != nil {
		ffiLogf("SetCookie: %v", err)
		return false
	}
	ffiLogf("SetCookie: ok (len=%d)", len(cookie))
	return true
}

//export GetPrefs
func GetPrefs() *C.char {
	ctx := context.Background()
	prefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		ffiLogf("GetPrefs: %v", err)
		return C.CString("{}")
	}

	j, _ := json.MarshalIndent(prefs, "", "\t")
	ffiLogf("GetPrefs:\n%s", string(j))

	return C.CString(string(j))
}

//export GetStatus
func GetStatus() *C.char {
	ctx := context.Background()
	st, err := localClient.Status(ctx)
	if err != nil {
		ffiLogf("GetStatus: %v", err)
		return C.CString("{}")
	}

	j, _ := json.MarshalIndent(st, "", "  ")
	ffiLogf("GetStatus:\n%s", string(j))

	return C.CString(string(j))
}

var netcheckArgs struct {
	format  string
	every   time.Duration
	verbose bool
}

//export GetNetcheck
func GetNetcheck() *C.char {
	netcheckArgs.format = "json"
	netcheckArgs.every = 0
	netcheckArgs.verbose = false

	ctx := context.Background()
	logf := logger.WithPrefix(ffiLogf, "portmap: ")
	bus := eventbus.New()
	netMon, err := netmon.New(bus, logf)
	if err != nil {
		ffiLogf("GetNetcheck: netmon: %v", err)
		return C.CString("{}")
	}
	pm := portmapper.NewClient(portmapper.Config{
		EventBus: bus,
		Logf:     logger.Discard,
		NetMon:   netMon,
	})
	pm.SetGatewayLookupFunc(netMon.GatewayAndSelfIP)

	c := &netcheck.Client{
		PortMapper:  pm,
		UseDNSCache: false, // always resolve, don't cache
	}
	if netcheckArgs.verbose {
		c.Logf = logger.WithPrefix(ffiLogf, "netcheck: ")
		c.Verbose = true
	} else {
		c.Logf = logger.Discard
	}

	if strings.HasPrefix(netcheckArgs.format, "json") {
		ffiLogf("GetNetcheck: JSON format is not a stable interface")
	}

	if err := c.Standalone(ctx, envknob.String("TS_DEBUG_NETCHECK_UDP_BIND")); err != nil {
		ffiLogf("GetNetcheck: UDP test failure: %v", err)
	}

	dm, err := localClient.CurrentDERPMap(ctx)
	noRegions := dm != nil && len(dm.Regions) == 0
	if noRegions {
		ffiLogf("GetNetcheck: no DERP map from tailscaled, using default")
	}
	if err != nil || noRegions {
		dm, err = prodDERPMap(ctx, http.DefaultClient)
		if err != nil {
			ffiLogf("GetNetcheck: fetch DERP map: %v", err)
			return C.CString("{}")
		}
	}

	t0 := time.Now()
	report, err := c.GetReport(ctx, dm, nil)
	d := time.Since(t0)
	if netcheckArgs.verbose {
		c.Logf("GetReport took %v; err=%v", d.Round(time.Millisecond), err)
	}
	if err != nil {
		ffiLogf("GetNetcheck: GetReport: %v", err)
		return C.CString("{}")
	}
	j, _ := json.MarshalIndent(report, "", "\t")
	ffiLogf("GetNetcheck (%v):\n%s", d.Round(time.Millisecond), string(j))

	return C.CString(string(j))
}

func portMapping(r *netcheck.Report) string {
	if !r.AnyPortMappingChecked() {
		return "not checked"
	}
	var got []string
	if r.UPnP.EqualBool(true) {
		got = append(got, "UPnP")
	}
	if r.PMP.EqualBool(true) {
		got = append(got, "NAT-PMP")
	}
	if r.PCP.EqualBool(true) {
		got = append(got, "PCP")
	}
	return strings.Join(got, ", ")
}

func prodDERPMap(ctx context.Context, httpc *http.Client) (*tailcfg.DERPMap, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", ipn.DefaultControlURL+"/derpmap/default", nil)
	if err != nil {
		return nil, fmt.Errorf("create prodDERPMap request: %w", err)
	}
	res, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch prodDERPMap failed: %w", err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("fetch prodDERPMap failed: %w", err)
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("fetch prodDERPMap: %v: %s", res.Status, b)
	}
	var derpMap tailcfg.DERPMap
	if err = json.Unmarshal(b, &derpMap); err != nil {
		return nil, fmt.Errorf("fetch prodDERPMap: %w", err)
	}
	return &derpMap, nil
}

func tailscalePingJSON(ip string, timeoutSec int) string {
	if timeoutSec <= 0 {
		timeoutSec = 5
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()
	st, err := localClient.Ping(ctx, netip.MustParseAddr(ip), tailcfg.PingDisco)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			ffiLogf("TailscalePing: %s: timeout", ip)
		} else {
			ffiLogf("TailscalePing: %s: %v", ip, err)
		}
		return "{}"
	}
	j, _ := json.MarshalIndent(st, "", "  ")
	ffiLogf("TailscalePing: %s: ok (%d bytes)", ip, len(j))
	return string(j)
}

//export TailscalePingAsync
func TailscalePingAsync(ipStr *C.char, timeout int, done C.Callback) *C.char {
	ip := C.GoString(ipStr)
	go func() {
		if done == nil {
			return
		}
		C.call_out(done, unsafe.Pointer(C.CString(tailscalePingJSON(ip, timeout))))
	}()
	return errorCString(nil)
}
