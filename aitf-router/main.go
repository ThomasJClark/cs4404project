package main

import "log"

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	go listenForFilterRequest()
	go addRouteRecords()

	select {}
}
