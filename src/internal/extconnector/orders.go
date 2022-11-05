/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - orders.go
==========================================================
Author: Alberto Dominguez

This package manages the interaction with the external connectors, as well as the control of their status.
This file contains everything regarding orders that can be sent to external connectors
*/

package extconnector

//--------------------------------
// Order type ENUM
//--------------------------------
type OrderType int

const (
	ConsOrdNone OrderType = iota
	ConsOrdAcceptConn
	ConsOrdNotAcceptConn
	ConsOrdShutdown
	ConsOrdReboot
	ConsOrdDisconnect
)

// method to provide text to each enum option
func (ot OrderType) String() string {
	// https://programming.guide/go/three-dots-ellipsis.html#array-literals
	return [...]string{"NONE", "ACCEPT_CONN", "NOT_ACCEPT_CONN", "SHUTDOWN",
		"REBOOT", "DISCONNECT"}[ot]
}
