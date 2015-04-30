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

/*
InstallFilter adds an iptables rule to implement the requested filter. The
filter will be removed after the specified duration has passed.
*/
func InstallFilter(req Request, d time.Duration) error {
	if req.Authentic() {
		requests = append(requests, &req)
		log.Printf("Added filter: (%s) to (%s) for %s", req.Source, req.Dest, d)

		go func() {
			time.Sleep(d)

			/*Remove the reqest from the array of currently active filters.*/
			for i, req2 := range requests {
				if &req == req2 {
					requests = append(requests[:i], requests[i+1:]...)
					break
				}
			}

			log.Printf("Removed filter: (%s) to (%s)", req.Source, req.Dest)
		}()

		return nil
	}

	return errors.New("The filter request is not authentic.")
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
