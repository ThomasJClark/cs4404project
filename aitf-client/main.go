package main

import (
	"flag"
	"log"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	/*Read in the command-line options.*/
	modeStr := flag.String("mode", "comply", "What to do after receiving a filter request (comply, ignore, or lie)")
	sendRequests := flag.Bool("sendRequests", false, "Enable the dummy policy module to send filter request. (true or false)")
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

	select {}
}
