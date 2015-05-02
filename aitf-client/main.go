package main

import (
	"flag"
	"log"
	"net"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	/*Read in the command-line options.*/
	modeStr := flag.String("mode", "comply", "What to do after receiving a filter request (comply, ignore, or lie)")
	sendRequests := flag.Bool("sendRequests", false, "Enable the dummy policy module to send filter request. (true or false)")
	fakeRequestVictim := flag.String("fakeRequestVictim", "", "Spam 10.4.32.1 with fake filter requests for the given IP.")
	flag.Parse()

	switch *modeStr {
	case "comply":
		log.Println("Complying with filtering requests.")
		go listenForFilterRequest(comply)
	case "ignore":
		log.Println("Ignoring filtering requests.")
		go listenForFilterRequest(ignore)
	case "lie":
		log.Println("Pretending to comply with filtering requests.")
		go listenForFilterRequest(lie)
	}

	go listenForRouteRecords(*sendRequests)

	if *fakeRequestVictim != "" {
		go sendFakeRequests(net.ParseIP(*fakeRequestVictim), net.ParseIP("10.4.32.1"))
	}

	select {}
}
