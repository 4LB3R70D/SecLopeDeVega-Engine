/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - syslog_alerts.go
=================================================
Author: Alberto Dominguez

This package manages the interaction with the alerting systems for sending alerts
according to the events registered. This file contains the logic of the syslog delivery
*/
package alerting

import (
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"

	syslog "github.com/RackSec/srslog"

	"sec-lope-de-vega/internal/englogging"
	"sec-lope-de-vega/internal/opvariables"
	"sec-lope-de-vega/internal/utils"
)

// Function to initialise the syslog alerting mechanism
func initSyslog(ctx *opvariables.Context) (bool, *syslog.Writer, string) {

	var enableSyslog bool
	var syslogger *syslog.Writer
	var err error
	var tlsConfig *tls.Config
	var privKeyLocation string

	if ctx.Cnfg.AlertingService.SysLog.Remote {
		// if remote syslog
		var syslogProtocol string
		if strings.ToUpper(ctx.Cnfg.AlertingService.SysLog.RemoteSyslogProtocol) == consSyslogProtocolTCP {
			syslogProtocol = "tcp"
		} else {
			syslogProtocol = "udp"
		}
		if ctx.Cnfg.AlertingService.SysLog.TLS.Enable {
			if enableSyslog, tlsConfig, privKeyLocation, err = utils.GetTlsConfig(ctx.EngineDir,
				ctx.Cnfg.AlertingService.SysLog.TLS.CaCert, ctx.Cnfg.AlertingService.SysLog.TLS.RelativePathForCertificates,
				ctx.Cnfg.AlertingService.SysLog.TLS.EngineClientKey, ctx.Cnfg.AlertingService.SysLog.TLS.EngineClientKeyProtected,
				ctx.Cnfg.AlertingService.SysLog.TLS.EngineClientKeyProtectedPassword,
				ctx.Cnfg.AlertingService.SysLog.TLS.EngineClientCert, ctx.Cnfg.AlertingService.SysLog.TLS.SkipCertificateVerification,
				ctx.Cnfg.AlertingService.SysLog.TLS.ServerName); err != nil {
				englogging.ErrorLog("Error loading the TLS config for Syslog", err)

			} else {
				syslogger, err = syslog.DialWithTLSConfig("tcp+tls",
					ctx.Cnfg.AlertingService.SysLog.RemoteSyslogServerIP+":"+
						strconv.Itoa(ctx.Cnfg.AlertingService.SysLog.RemoteSyslogPort),
					syslog.LOG_INFO,
					ctx.Cnfg.AlertingService.SysLog.SyslogTag,
					tlsConfig)
			}
		} else {
			syslogger, err = syslog.Dial(syslogProtocol,
				ctx.Cnfg.AlertingService.SysLog.RemoteSyslogServerIP+":"+
					strconv.Itoa(ctx.Cnfg.AlertingService.SysLog.RemoteSyslogPort),
				syslog.LOG_INFO,
				ctx.Cnfg.AlertingService.SysLog.SyslogTag)
		}
	} else {
		//local syslog
		syslogger, err = syslog.New(syslog.LOG_INFO,
			ctx.Cnfg.AlertingService.SysLog.SyslogTag)
	}
	if err != nil {
		englogging.ErrorLog("Not possible to initialise the Syslog Alerting mechanism", err)
	} else {
		enableSyslog = true
	}
	return enableSyslog, syslogger, privKeyLocation
}

// Function to write in the syslog writer
func (aleser *AlertingService) sendSyslogAlert(activity opvariables.ExtActivity) {

	activityContent := utils.PrepareActivityToBeExported(activity.GetActivityContent(), activity.Hash,
		activity.Signature, activity.PubKeyActivitySignature, activity.HashConvRules, aleser.encodeB64Syslog)

	aleser.syslogMutex.Lock()
	defer aleser.syslogMutex.Unlock()
	fmt.Fprint(aleser.syslogWriter, activityContent)
}
