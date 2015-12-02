package main

import (
	"flag"
	"log"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	/*Read in the command-line options.*/
	modeStr := flag.String("mode", "comply", "What to do after receiving a filter request (comply, ignore, or lie)")
	flag.Parse()

	switch *modeStr {
	case "ignore":
		log.Println("Ignoring filtering requests.")
		go listenForFilterRequest(ignore)
	case "lie":
		log.Println("Pretending to comply with filtering requests.")
		go listenForFilterRequest(lie)
	default:
		log.Println("Complying with filtering requests.")
		go listenForFilterRequest(comply)
	}

	go addRouteRecords()

	select {}
}
