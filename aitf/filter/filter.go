package filter

import (
	"errors"
	"log"
	"net"
	"time"
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
		log.Printf("Added filter: (%s to %s) for %s", req.Source, req.Dest, d)

		go func() {
			time.Sleep(d)
			UninstallFilter(req)
			log.Printf("Removed filter: (%s to %s)", req.Source, req.Dest)
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
		if req.Source.Equal(req2.Source) && req.Dest.Equal(req2.Dest) {
			requests = append(requests[:i], requests[i+1:]...)
			break
		}
	}
}

/*IsFiltered returns true if there is currently a filter in place blocking
the given hosts from communicating in this direction.*/
func IsFiltered(source, dest net.IP) bool {
	for _, req := range requests {
		if req.Source.Equal(source) && req.Dest.Equal(dest) {
			return true
		}
	}
	return false
}
