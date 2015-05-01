package main

type filterAction int

const (
	comply filterAction = iota
	ignore
	lie
)

/*
listenForFilterRequest waits for a filter request from a router to come.  Then,
it verifies the authenticity of the request and takes some action.

If action is comply, it filters the attack.

If action is ignore, it logs the request but does nothing about it.

If action is lie, it complies with the request but doesn't actually add a filter.
*/
func listenForFilterRequest(action filterAction) {
}
