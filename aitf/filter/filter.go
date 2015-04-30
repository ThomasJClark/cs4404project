package filter

import (
	"errors"
	"log"
	"net"
	"os/exec"
	"time"
)

/*
InstallFilter adds an iptables rule to implement the requested filter. The
filter will be removed after the specified duration has passed.
*/
func InstallFilter(req Request, d time.Duration) error {
	if req.Authentic() {
		addIPTablesFilter(req.Source, req.Dest)
		log.Printf("Added filter: (%s) to (%s) for %s", req.Source, req.Dest, d)

		go func() {
			time.Sleep(d)
			removeIPTablesFilter(req.Source, req.Dest)
			log.Printf("Removed filter: (%s) to (%s)", req.Source, req.Dest)
		}()

		return nil
	}

	return errors.New("The filter request is not authentic.")
}

func addIPTablesFilter(source, dest net.IP) error {
	cmd := exec.Command("iptables", "-A", "INPUT", "-s", source.String(), "-d",
		dest.String(), "-j", "DROP")
	return cmd.Run()
}

/*
RemoveFilter removes the iptables rule that implements the given filter request
*/
func removeIPTablesFilter(source, dest net.IP) error {
	cmd := exec.Command("iptables", "-D", "INPUT", "-s", source.String(), "-d",
		dest.String(), "-j", "DROP")
	return cmd.Run()
}
