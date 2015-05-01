package filter

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"time"

	"github.com/ThomasJClark/cs4404project/aitf"
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

If forward is true, the rule will block forwarded traffic.  This option is true
for routers.

This function returns immediately, and the rule is applied and removed
asynchronously.
*/
func InstallFilter(req Request, d time.Duration, forward bool) error {
	if req.Authentic() {
		log.Printf("Adding filter: [%s to %s] for %s", aitf.Hostname(req.SrcIP), aitf.Hostname(req.DstIP), d)

		/*Run the iptables command to add the filter in a goroutine so we don't
		block until it finishes.*/
		go func() {
			var target string
			if forward {
				target = "FORWARD"
			} else {
				target = "OUTPUT"
			}

			cmd := exec.Command("iptables",
				"-I", target,
				"-s", fmt.Sprintf("%s/32", req.SrcIP),
				"-d", fmt.Sprintf("%s/32", req.DstIP),
				"-j", "DROP")

			err := cmd.Run()
			if err != nil {
				log.Println(err)
				return
			}

			/*Uninstall the filter after sleeping for d*/
			go func() {
				time.Sleep(d)
				log.Println("Filter timed out.")
				UninstallFilter(req, forward)
			}()
		}()

		return nil
	}

	return errors.New("The filter request is not authentic.")
}

/*
UninstallFilter removes the firewall rule associated with the specified filter
request.

If forward is true, the rule blocks forwarded traffic.  This option is true
for routers.

This function returns immediately, and the rule is removed asynchronously.
*/
func UninstallFilter(req Request, forward bool) {
	var target string
	if forward {
		target = "FORWARD"
	} else {
		target = "OUTPUT"
	}

	/*Run the iptables command to remove the filter.*/
	cmd := exec.Command("iptables",
		"-D", target,
		"-s", fmt.Sprintf("%s/32", req.SrcIP),
		"-d", fmt.Sprintf("%s/32", req.DstIP),
		"-j", "DROP")

	go func() {
		/*If the command fails, it's because the filter has already been removed.
		This happens all the time, since all temporary filters are automatically
		removed after a timeout, weather or not they have already been legitimately
		removed.*/
		if cmd.Run() == nil {
			log.Printf("Removing filter: [%s to %s]", aitf.Hostname(req.SrcIP), aitf.Hostname(req.DstIP))
			return
		}
	}()
}
