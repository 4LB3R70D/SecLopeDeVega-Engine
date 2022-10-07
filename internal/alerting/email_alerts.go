/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - email_alerts.go
=================================================
Author: Alberto Dominguez

This package manages the interaction with the alerting systems for sending alerts
according to the events registered. This file contains the logic of the email delivery
*/
package alerting

import (
	"crypto/tls"
	"fmt"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"

	"sec-lope-de-vega/internal/englogging"
	"sec-lope-de-vega/internal/opvariables"
	"sec-lope-de-vega/internal/utils"
	"github.com/jordan-wright/email"
)

// https://github.com/jordan-wright/email
// https://pkg.go.dev/github.com/jordan-wright/email?utm_source=godoc

const (
	consCramMd5Auth = "CRAMMD5"
)

// Function to initialise the email delivery mechanism
func initEmailDelivery(ctx *opvariables.Context) (bool, smtp.Auth, *tls.Config, string) {

	var enableMailDelivery bool
	var tlsConfig *tls.Config
	var err error
	var privKeyLocation string
	var auth smtp.Auth

	if strings.ToUpper(ctx.Cnfg.AlertingService.Email.AuthN) == consCramMd5Auth {
		auth = smtp.CRAMMD5Auth(
			ctx.Cnfg.AlertingService.Email.SmtpAuthUser,
			ctx.Cnfg.AlertingService.Email.SmtpAuthPassword)
	} else {
		auth = smtp.PlainAuth(
			ctx.Cnfg.AlertingService.Email.SmtpPlainAuthIdentity,
			ctx.Cnfg.AlertingService.Email.SmtpAuthUser,
			ctx.Cnfg.AlertingService.Email.SmtpAuthPassword,
			ctx.Cnfg.AlertingService.Email.SmtpPlainAuthHost)
	}
	if ctx.Cnfg.AlertingService.Email.TLS.Enable {
		if enableMailDelivery, tlsConfig, privKeyLocation, err = utils.GetTlsConfig(ctx.EngineDir,
			ctx.Cnfg.AlertingService.Email.TLS.CaCert, ctx.Cnfg.AlertingService.Email.TLS.RelativePathForCertificates,
			ctx.Cnfg.AlertingService.Email.TLS.EngineClientKey, ctx.Cnfg.AlertingService.Email.TLS.EngineClientKeyProtected,
			ctx.Cnfg.AlertingService.Email.TLS.EngineClientKeyProtectedPassword,
			ctx.Cnfg.AlertingService.Email.TLS.EngineClientCert, ctx.Cnfg.AlertingService.Email.TLS.SkipCertificateVerification,
			ctx.Cnfg.AlertingService.Email.TLS.ServerName); err != nil {
			englogging.ErrorLog("Error loading the TLS config for emails", err)
		}
	} else {
		enableMailDelivery = ctx.Cnfg.AlertingService.Email.Enable
	}
	return enableMailDelivery, auth, tlsConfig, privKeyLocation
}

// Function to remove invalid emails from a list of them
func removeInvalidEmails(emailList []string) []string {

	validListOfEmails := make([]string, 0)
	for _, potentialEmail := range emailList {
		if _, err := mail.ParseAddress(potentialEmail); err == nil {
			validListOfEmails = append(validListOfEmails, potentialEmail)
		}
	}
	return validListOfEmails
}

// Function to send an email alert
func (aleser *AlertingService) sendAlertEmail(activity opvariables.ExtActivity) {

	// Email object
	alertEmail := email.NewEmail()
	alertEmail.From = aleser.from
	if len(removeInvalidEmails(aleser.to)) > 0 {
		alertEmail.To = aleser.to
	}
	if len(removeInvalidEmails(aleser.bcc)) > 0 {
		alertEmail.Bcc = aleser.bcc
	}
	if len(removeInvalidEmails(aleser.cc)) > 0 {
		alertEmail.Cc = aleser.cc
	}
	alertEmail.Subject = aleser.subject
	if len(removeInvalidEmails(aleser.replyTo)) > 0 {
		alertEmail.ReplyTo = aleser.replyTo
	} else {
		defaultReplyTo := make([]string, 0)
		defaultReplyTo = append(defaultReplyTo, aleser.from)
		alertEmail.ReplyTo = defaultReplyTo
	}

	// Activity content
	activityContent := utils.PrepareActivityToBeExported(activity.GetActivityContent(), activity.Hash, activity.Signature,
		activity.PubKeyActivitySignature, activity.HashConvRules, aleser.encodeB64Email)

	emailContent := fmt.Sprintf("%s%s%s",
		aleser.bodyIntroEmail,
		activityContent,
		aleser.bodyEndEmail)
	alertEmail.HTML = []byte(emailContent)

	// Sending email
	var err error
	aleser.mailMutex.Lock()
	defer aleser.mailMutex.Unlock()

	if aleser.encryptedEmail && !aleser.startTls {
		err = alertEmail.SendWithTLS(aleser.smtpIp+":"+strconv.Itoa(aleser.smtpPort), aleser.emailAuth, aleser.emailTlsConfig)

	} else if aleser.encryptedEmail && aleser.startTls {
		err = alertEmail.SendWithStartTLS(aleser.smtpIp+":"+strconv.Itoa(aleser.smtpPort), aleser.emailAuth, aleser.emailTlsConfig)

	} else {
		err = alertEmail.Send(aleser.smtpIp+":"+strconv.Itoa(aleser.smtpPort), aleser.emailAuth)
	}
	if err != nil {
		englogging.ErrorLog("Something was wrong at the time of sending an email alert.", err)
	}
}
