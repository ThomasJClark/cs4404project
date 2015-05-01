package filter

import (
	"errors"
	"log"
	"net"
	"time"

	"github.com/ThomasJClark/cs4404project/aitf"
)

var (
	requests = []*Request{}
)

const (
	/*TemporaryFilterTime is the time that routers block flows while waiting for
	an attacker or a router closer to the attacker to install a longer-lasting
	filter.*/
	TemporaryFilterTime = time.Second

	/*LongFilterTime is the time that flows are ultimately blocked for by
	the attacking host or a nearby router.*/
	LongFilterTime = 2 * time.Minute
)

/*
InstallFilter adds a firewall rule to implement the requested filter. The
filter will be removed after the specified duration has passed.
*/
func InstallFilter(req Request, d time.Duration) error {
	if req.Authentic() {
		requests = append(requests, &req)
		log.Printf("Added filter: (%s to %s) for %s", aitf.Hostname(req.SrcIP), aitf.Hostname(req.DstIP), d)

		go func() {
			time.Sleep(d)

			if IsFiltered(req.SrcIP, req.DstIP) {
				log.Println("Filter timed out.")
				UninstallFilter(req)
			}
		}()

		return nil
	}

	return errors.New("The filter request is not authentic.")
}

/*UninstallFilter removes the rule associated with the specified filter request
early.*/
func UninstallFilter(req Request) {
	/*Remove the reqest from the array of currently active filters.*/
	for i, req2 := range requests {
		if req.SrcIP.Equal(req2.SrcIP) && req.DstIP.Equal(req2.DstIP) {
			requests = append(requests[:i], requests[i+1:]...)
			log.Printf("Removed filter: (%s to %s)", aitf.Hostname(req.SrcIP), aitf.Hostname(req.DstIP))
			return
		}
	}
}

/*IsFiltered returns true if there is currently a filter in place blocking
the given hosts from communicating in this direction.*/
func IsFiltered(source, dest net.IP) bool {
	for _, req := range requests {
		if req.SrcIP.Equal(source) && req.DstIP.Equal(dest) {
			return true
		}
	}
	return false
}
