/*
  set GOOS=windows
  set GOARCH=amd64
  go build -v -buildmode=c-shared -o tailscale-ffi.dll ./cmd/tailscale-ffi
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	cli "tailscale.com/cmd/tailscale/cli"
	"unsafe"

	//"syscall/js"

	"tailscale.com/client/tailscale"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/portmapper"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
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

func main() {
	// fmt.Println(RunWithArgs(C.CString("aaaa"), C.CString("bbbb")))
}

//export RunWithArgs
func RunWithArgs(argstr *C.char) string {
	arg_str := C.GoString(argstr)
	fmt.Printf("args: %v\n", arg_str)
	args := strings.Split(arg_str, " ")
	fmt.Println(args)
	if err := cli.Run(args); err != nil {
		log.Printf("cli.Run error: %+v\n", err)
		//        os.Exit(1)
		return "some error"
	}

	return ""
}

var localClient tailscale.LocalClient

//export WatchIPN
func WatchIPN(argstr *C.char, initial bool, callback C.Callback) *C.char {
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
			log.Println("WatchIPNBus", err)
			return
		}
		defer watcher.Close()
		log.Printf("Connected.\n")
		for {
			n, err := watcher.Next()
			if err != nil {
				log.Println("watcher.Next() -> ", err)
				j, _ := json.MarshalIndent(n, "", "\t")
				//printf("%s\n", j)

				C.call_out(callback, unsafe.Pointer(C.CString(string(j))))
				return
			}
			if !watchIPNArgs.netmap {
				n.NetMap = nil
			}
			j, _ := json.MarshalIndent(n, "", "\t")
			//printf("%s\n", j)

			C.call_out(callback, unsafe.Pointer(C.CString(string(j))))
			if initial {
				break
			}
		}
	}()
	return C.CString("") //C.CString(string(j))
}

//export SetCookie
func SetCookie(cookiestr *C.char) bool {
	cookie := C.GoString(cookiestr)
	fmt.Printf("args: %v\n", cookie)
	ctx := context.Background()
	err := localClient.SetDevStoreKeyValue(ctx, "Cookie", cookie)
	if err != nil {
		log.Println("SetDevStoreKeyValue", err)
		return false
	}

	log.Println("set cookie successful")
	return true
}

//export GetPrefs
func GetPrefs() *C.char {
	ctx := context.Background()
	prefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return C.CString("{}")
	}

	j, _ := json.MarshalIndent(prefs, "", "\t")
	log.Println(string(j))

	return C.CString(string(j))
}

//export GetStatus
func GetStatus() *C.char {
	ctx := context.Background()
	st, err := localClient.Status(ctx)
	if err != nil {
		return C.CString("{}")
	}

	j, _ := json.MarshalIndent(st, "", "  ")
	log.Println(string(j))

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
	logf := logger.WithPrefix(log.Printf, "portmap: ")
	netMon, err := netmon.New(logf)
	if err != nil {
		//return err
		return C.CString("{}")
	}
	c := &netcheck.Client{
		PortMapper:  portmapper.NewClient(logger.Discard, netMon, nil, nil),
		UseDNSCache: false, // always resolve, don't cache
	}
	if netcheckArgs.verbose {
		c.Logf = logger.WithPrefix(log.Printf, "netcheck: ")
		c.Verbose = true
	} else {
		c.Logf = logger.Discard
	}

	if strings.HasPrefix(netcheckArgs.format, "json") {
		fmt.Fprintln(os.Stderr, "# Warning: this JSON format is not yet considered a stable interface")
	}

	if err := c.Standalone(ctx, envknob.String("TS_DEBUG_NETCHECK_UDP_BIND")); err != nil {
		fmt.Fprintln(os.Stderr, "netcheck: UDP test failure:", err)
	}

	dm, err := localClient.CurrentDERPMap(ctx)
	noRegions := dm != nil && len(dm.Regions) == 0
	if noRegions {
		log.Printf("No DERP map from tailscaled; using default.")
	}
	if err != nil || noRegions {
		dm, err = prodDERPMap(ctx, http.DefaultClient)
		if err != nil {
			//return err
			return C.CString("{}")
		}
	}

	t0 := time.Now()
	report, err := c.GetReport(ctx, dm)
	d := time.Since(t0)
	if netcheckArgs.verbose {
		c.Logf("GetReport took %v; err=%v", d.Round(time.Millisecond), err)
	}
	if err != nil {
		//return fmt.Errorf("netcheck: %w", err)
		return C.CString("{}")
	}
	j, _ := json.MarshalIndent(report, "", "\t")
	log.Println(string(j))

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
