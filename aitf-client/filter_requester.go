package main

import (
	"log"

	"github.com/ThomasJClark/cs4404project/aitf/filter"
)

/*sendRequest constructs and sends a request for the given flow to stop. It
should escalate the request if necessary.*/
func sendRequest(req filter.Request) {
	attackerRouter := req.Flow.Path[0]
	log.Println("Contacting", attackerRouter.Address, "to deal with this nonsense.")
}
