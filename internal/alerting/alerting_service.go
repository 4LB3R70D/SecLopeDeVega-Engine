/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - alerting_service.go
=================================================
Author: Alberto Dominguez

This package manages the interaction with the alerting systems for sending alerts
according to the events registered. This file contains the logic of the service
*/
package alerting

import (
	"crypto/tls"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"sync"
	"time"

	"sec-lope-de-vega/internal/englogging"
	"sec-lope-de-vega/internal/messages"
	"sec-lope-de-vega/internal/opvariables"
	"github.com/RackSec/srslog"
	"github.com/segmentio/kafka-go"
)

const (
	// Simple file storage
	consDefaultNumberOfAlertWorkers = 200
	consSyslogProtocolTCP           = "TCP"
	consDefaultLocalUrl             = "http://127.0.0.1"
	consSafeEndingTime              = 3 // seconds
)

//  "object" for the daata service
type AlertingService struct {
	working           bool
	toEngineCockpit   chan<- messages.ChannelMessage
	toAlertingService <-chan messages.ChannelMessage

	// concurrence material
	aleServiceMutex *sync.Mutex
	syslogMutex     *sync.Mutex
	httpMutex       *sync.Mutex
	mailMutex       *sync.Mutex
	kafkaMutex      *sync.Mutex
	numberWorkers   int
	maxWorkers      int

	// syslog alerting
	enableSyslog          bool
	syslogWriter          *srslog.Writer
	syslogPrivKeyLocation string
	syslogKeyProtected    bool
	encodeB64Syslog       bool

	// http client alerting
	enableHttp          bool
	httpClient          *http.Client
	httpMethod          string
	httpUrl             string
	useHttpBody         bool
	headers             map[string]string
	urlParameters       map[string]string
	bodyIntroHttp       string
	bodyEndHttp         string
	encodeB64Http       bool
	httpPrivKeyLocation string
	httpKeyProtected    bool
	encryptedHttp       bool

	// kafka alerting
	enableKafka          bool
	kafkaWriter          *kafka.Writer
	kafkaEventKey        string
	kafkaPrivKeyLocation string
	kafkaKeyProtected    bool
	kafkaTimeout         time.Duration
	encodeB64Kafka       bool

	// email alerting
	enableMailDelivery   bool
	emailAuth            smtp.Auth
	emailTlsConfig       *tls.Config
	startTls             bool
	encryptedEmail       bool
	smtpIp               string
	smtpPort             int
	from                 string
	to                   []string
	cc                   []string
	bcc                  []string
	replyTo              []string
	subject              string
	bodyIntroEmail       string
	bodyEndEmail         string
	emailPrivKeyLocation string
	emailKeyProtected    bool
	encodeB64Email       bool
}

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 'Private' functions: service related ones
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// Method to end the execution of an alerting service
func (aleser *AlertingService) stop() {

	aleser.working = false

	// final time before ending to ensure the rest of the threads ends correctly
	time.Sleep(time.Duration(consSafeEndingTime) * time.Second)

	if aleser.syslogKeyProtected {
		if err := os.Remove(aleser.syslogPrivKeyLocation); err != nil {
			englogging.ErrorLog("Deleting the temporary file where the key is unencrypted was not possible for the syslog TLS", err)
		}
	}
	if aleser.httpKeyProtected {
		if err := os.Remove(aleser.httpPrivKeyLocation); err != nil {
			englogging.ErrorLog("Deleting the temporary file where the key is unencrypted was not possible for the http TLS", err)
		}
	}
	if aleser.enableKafka {
		if aleser.kafkaKeyProtected {
			if err := os.Remove(aleser.kafkaPrivKeyLocation); err != nil {
				englogging.ErrorLog("Deleting the temporary file where the key is unencrypted was not possible for the kafka TLS", err)
			}
		}
		if err := aleser.kafkaWriter.Close(); err != nil {
			englogging.ErrorLog("Not possible to close the Kafka client writer", err)
		}
	}
	if aleser.emailKeyProtected {
		if err := os.Remove(aleser.emailPrivKeyLocation); err != nil {
			englogging.ErrorLog("Deleting the temporary file where the key is unencrypted was not possible for the email TLS", err)
		}
	}
	englogging.WarnLog("ALERTING SERVICE ENDED!", nil)
}

// Function to process the orders received from the engine cockpit
func (aleser *AlertingService) processInternalOrder(intOrd messages.IntOrder) {

	if intOrd == messages.ConsStopOrder {
		aleser.stop()
	}
}

// Method to increase the number of alert workers in use
func (aleser *AlertingService) increaseNumberOfAlertWorkers() {

	aleser.aleServiceMutex.Lock()
	defer aleser.aleServiceMutex.Unlock()
	aleser.numberWorkers++
}

// Method to decrease the number of alert workers in use
func (aleser *AlertingService) decreaseNumberOfAlertWorkers() {

	aleser.aleServiceMutex.Lock()
	defer aleser.aleServiceMutex.Unlock()
	aleser.numberWorkers--
}

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 'Private' functions: internal order related ones
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// Function to send alerts of activity according to the configuration
func (aleser *AlertingService) notifyNewActivity(activity opvariables.ExtActivity) {

	if aleser.enableSyslog && (activity.AlertAll || activity.AlertSyslog) {
		aleser.sendSyslogAlert(activity)
	}
	if aleser.enableHttp && (activity.AlertAll || activity.AlertHttp) {
		aleser.sendHttpAlert(activity)
	}
	if aleser.enableKafka && (activity.AlertAll || activity.AlertKafka) {
		aleser.sendKafkaAlert(activity)
	}
	if aleser.enableMailDelivery && (activity.AlertAll || activity.AlertEmail) {
		aleser.sendAlertEmail(activity)
	}
	aleser.decreaseNumberOfAlertWorkers()
}

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// PUBLIC FUNCTIONS
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

//function to create a new data service
func CreateAlertingService(ctx *opvariables.Context, myToEngineCockpit chan<- messages.ChannelMessage,
	myToAlertingService <-chan messages.ChannelMessage) *AlertingService {

	maxNumberOfAlertWorkers := consDefaultNumberOfAlertWorkers
	if ctx.Cnfg.AlertingService.MaxNumberOfAlertWorkers > 0 {
		maxNumberOfAlertWorkers = ctx.Cnfg.AlertingService.MaxNumberOfAlertWorkers
	}

	// Syslog initialisation
	var enableSyslog bool
	var syslogger *srslog.Writer
	var privKeyLocationSyslog string
	if ctx.Cnfg.AlertingService.SysLog.Enable {
		enableSyslog, syslogger, privKeyLocationSyslog = initSyslog(ctx)
	}

	// HTTP client initialisation
	var enableHttpClient bool
	var httpClient *http.Client
	var httpMethod string
	var httpPrivKeyLocationSyslog string
	var httpUrl string
	if ctx.Cnfg.AlertingService.Http.Enable {
		if len(ctx.Cnfg.AlertingService.Http.Url) >= 0 {
			httpUrl = ctx.Cnfg.AlertingService.Http.Url
		} else {
			httpUrl = consDefaultLocalUrl
		}
		enableHttpClient, httpClient, httpMethod, httpPrivKeyLocationSyslog = initHttpClient(ctx)
	}

	// Email initialisation
	var enableMailDelivery bool
	var auth smtp.Auth
	var emailTlsConfig *tls.Config
	var privKeyLocationEmail string
	if ctx.Cnfg.AlertingService.Email.Enable {
		enableMailDelivery, auth, emailTlsConfig, privKeyLocationEmail = initEmailDelivery(ctx)
	}

	// Kafka initialisation
	var enableKafka bool
	var kafkaWriter *kafka.Writer
	var privKeyLocationKafka string
	if ctx.Cnfg.AlertingService.KafKa.Enable {
		enableKafka, kafkaWriter, privKeyLocationKafka = initKafka(ctx)
	}

	// Service initialisation
	alertingService := AlertingService{
		working:           true,
		toEngineCockpit:   myToEngineCockpit,
		toAlertingService: myToAlertingService,

		// concurrence material
		aleServiceMutex: &sync.Mutex{},
		numberWorkers:   0,
		maxWorkers:      maxNumberOfAlertWorkers,

		// Syslog
		enableSyslog:          enableSyslog,
		syslogWriter:          syslogger,
		syslogMutex:           &sync.Mutex{},
		syslogPrivKeyLocation: privKeyLocationSyslog,
		encodeB64Syslog:       ctx.Cnfg.AlertingService.SysLog.EncodeB64,

		syslogKeyProtected: ctx.Cnfg.AlertingService.SysLog.TLS.Enable &&
			ctx.Cnfg.AlertingService.SysLog.TLS.EngineClientKeyProtected,

		// Http Client
		enableHttp:          enableHttpClient,
		httpMutex:           &sync.Mutex{},
		httpClient:          httpClient,
		httpMethod:          httpMethod,
		httpUrl:             httpUrl,
		useHttpBody:         ctx.Cnfg.AlertingService.Http.UseBody,
		encodeB64Http:       ctx.Cnfg.AlertingService.Http.EncodeB64,
		headers:             ctx.Cnfg.AlertingService.Http.Headers,
		urlParameters:       ctx.Cnfg.AlertingService.Http.UrlParameters,
		bodyIntroHttp:       ctx.Cnfg.AlertingService.Http.BodyIntro,
		bodyEndHttp:         ctx.Cnfg.AlertingService.Http.BodyEnd,
		httpPrivKeyLocation: httpPrivKeyLocationSyslog,
		encryptedHttp:       ctx.Cnfg.AlertingService.Http.TLS.Enable,

		httpKeyProtected: ctx.Cnfg.AlertingService.Http.TLS.Enable &&
			ctx.Cnfg.AlertingService.Http.TLS.EngineClientKeyProtected,

		// Kafka
		enableKafka:          enableKafka,
		kafkaMutex:           &sync.Mutex{},
		kafkaWriter:          kafkaWriter,
		kafkaTimeout:         time.Duration(ctx.Cnfg.AlertingService.KafKa.TimeOut) * time.Second,
		kafkaEventKey:        ctx.Cnfg.AlertingService.KafKa.EventKey,
		kafkaPrivKeyLocation: privKeyLocationKafka,
		encodeB64Kafka:       ctx.Cnfg.AlertingService.KafKa.EncodeB64,

		kafkaKeyProtected: ctx.Cnfg.AlertingService.KafKa.TLS.Enable &&
			ctx.Cnfg.AlertingService.KafKa.TLS.EngineClientKeyProtected,

		// email
		enableMailDelivery:   enableMailDelivery,
		mailMutex:            &sync.Mutex{},
		emailAuth:            auth,
		emailTlsConfig:       emailTlsConfig,
		encryptedEmail:       ctx.Cnfg.AlertingService.Email.TLS.Enable,
		smtpIp:               ctx.Cnfg.AlertingService.Email.SmtpIp,
		smtpPort:             ctx.Cnfg.AlertingService.Email.SmtpPort,
		from:                 ctx.Cnfg.AlertingService.Email.From,
		to:                   ctx.Cnfg.AlertingService.Email.To,
		replyTo:              ctx.Cnfg.AlertingService.Email.ReplyTo,
		cc:                   ctx.Cnfg.AlertingService.Email.CC,
		bcc:                  ctx.Cnfg.AlertingService.Email.BCC,
		subject:              ctx.Cnfg.AlertingService.Email.Subject,
		bodyIntroEmail:       ctx.Cnfg.AlertingService.Email.BodyIntro,
		bodyEndEmail:         ctx.Cnfg.AlertingService.Email.BodyEnd,
		emailPrivKeyLocation: privKeyLocationEmail,
		startTls:             ctx.Cnfg.AlertingService.Email.TLS.UseStartTLS,
		encodeB64Email:       ctx.Cnfg.AlertingService.Email.EncodeB64,

		emailKeyProtected: ctx.Cnfg.AlertingService.Email.TLS.Enable &&
			ctx.Cnfg.AlertingService.Email.TLS.EngineClientKeyProtected,
	}
	return &alertingService
}

// Method to start the execution of an alerting service
func (aleser *AlertingService) Start() {

	englogging.InfoLog("Starting alerting service in a new thread", nil)
	for aleser.working {
		msg := <-aleser.toAlertingService

		if msg.Type == messages.ConsActivity {
			activity := msg.Content.(opvariables.ExtActivity)

			waiting := true
			for waiting {
				// wait until the number of alert workers decreases
				if aleser.numberWorkers < aleser.maxWorkers {
					// Check if this activity should be reported, or not
					if activity.AlertAll || activity.AlertEmail || activity.AlertHttp ||
						activity.AlertKafka || activity.AlertSyslog {
						aleser.increaseNumberOfAlertWorkers()
						go aleser.notifyNewActivity(activity)
					} else {
						englogging.DebugLog("Nothing to report for the activity ID: '"+strconv.Itoa(activity.ID)+"'", nil)
					}
					waiting = false
				}
			}
		} else if msg.Type == messages.ConsOrder {
			intOrd := msg.Content.(messages.IntOrder)
			aleser.processInternalOrder(intOrd)
		}
	}
}
