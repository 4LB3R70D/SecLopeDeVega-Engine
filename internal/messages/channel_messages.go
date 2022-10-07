/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - channel_messages.go
=================================================
Author: Alberto Dominguez

This package contains the main message logic used in the engine.
This file contains logic about the messages send between threads
*/

package messages

// ====================================================
// CHANNEL MESSAGES
// ====================================================

//ENUM in GO: https://yourbasic.org/golang/iota/
// https://stackoverflow.com/questions/14426366/what-is-an-idiomatic-way-of-representing-enums-in-go

//--------------------------------
// Channel message sender ENUM
//--------------------------------
type ChSender int

const (
	ConsCockpitThread ChSender = iota
	ConsExtConnManagerThread
	ConsExtConnWorkerThread
	ConsDataThread
	ConsAPIWebServiceThread
	ConsPortalCommThread
)

// method to provide text to each enum option
func (cma ChSender) String() string {
	// https://programming.guide/go/three-dots-ellipsis.html#array-literals
	return [...]string{"COCKPIT", "EXTERNAL_CONNECTOR_MANAGER_SERVICE",
		"EXTERNAL_CONNECTOR_WORKER", "DATA_SERVICE", "API_WEB_SERVICE",
		"PORTAL_COMM_SERVICE"}[cma]
}

//--------------------------------
// Channel message sender ENUM
//--------------------------------
type IntOrder int

const (
	ConsPrepareEndOrder IntOrder = iota
	ConsStopOrder
)

// method to provide text to each enum option
func (intOrd IntOrder) String() string {
	// https://programming.guide/go/three-dots-ellipsis.html#array-literals
	return [...]string{"PREPARE_END", "STOP"}[intOrd]
}

//--------------------------------
// Channel message type ENUM
//--------------------------------
type ChMessageType int

const (
	ConsOrder ChMessageType = iota
	ConsActivity
	ConsExtConnWorkerDecreaseWorkerCounter
)

// method to provide text to each enum option
func (cmt ChMessageType) String() string {
	// https://programming.guide/go/three-dots-ellipsis.html#array-literals
	return [...]string{"ORDER", "ACTIVITY", "EXT_CONN_WORKER_DECREASE_WORKER_COUNTER"}[cmt]
}

//--------------------------------
// Message struct / object
//--------------------------------

// ChannelMessage is a message format for exchanging information between
// engine threads
type ChannelMessage struct {
	Sender  ChSender      // sender of the message
	Type    ChMessageType // kind of message
	Content interface{}
}
