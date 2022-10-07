/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - engine_logger.go
=================================================
Author: Alberto Dominguez

This package (engine logging) and this file contains a wrapper of zero log to do it thread-safe by
 adding 'locks'
*/
package englogging

import (
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"sec-lope-de-vega/internal/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/natefinch/lumberjack.v2"
)

// ===================================================================================================================
// ENGINE LOGGER CONSTANTS
// ===================================================================================================================
const (
	//logging levels
	consLogLevelTrace = "TRACE"
	consLogLevelDebug = "DEBUG"
	consLevelWarn     = "WARN"
	consLogLevelError = "ERROR"
	//logging mode
	consLogModeBoth         = "BOTH"
	consLogModeFile         = "FILE"
	consLogModeFileRotating = "FILE_ROTATING"
	consLogModeBothRotating = "BOTH_ROTATING"
	//logging log file
	consLogFileName = "slv_engine"
	consLogFileExt  = ".log"
	// external activity logging
	consExternalActivityLogKey = "EXTERNAL_ACTIVITY"
)

// ===================================================================================================================
// ENGINE LOGGER VARIABLES
// ===================================================================================================================
var (
	//logging lock for avoiding race conditions in the logger
	logMutex = &sync.Mutex{}
	// operation flag to use async logs
	asyncLogsFlag bool = false
)

// ===================================================================================================================
// ENGINE LOGGER FUNCTIONS
// ===================================================================================================================

// function to get the log file name
func getLogFileName(logPrefix, logExtension string) string {

	currentTime := time.Now()
	// get the log file name
	var logFilePrefix string
	var logFileExt string

	if len(logPrefix) > 0 {
		logFilePrefix = logPrefix
	} else {
		logFilePrefix = consLogFileName
	}
	if len(logExtension) > 0 {
		logFileExt = logExtension
	} else {
		logFileExt = consLogFileExt
	}
	logFileName := fmt.Sprint(logFilePrefix, "_", currentTime.Year(), "-", currentTime.Month(), "-", currentTime.Day(), "_",
		currentTime.Hour(), ":", currentTime.Minute(), ":", currentTime.Second(), logFileExt)
	return logFileName
}

// function to get a log file name
func getLogFile(engineDir, logFolderPath string, IsRelativePathFlag bool, logPrefix, LogExtension string) (*os.File, error) {

	logFileName := getLogFileName(logPrefix, LogExtension)
	logFile, err := utils.CreateNewFile(engineDir, logFolderPath, logFileName, IsRelativePathFlag)
	return logFile, err
}

// Auxiliary function to get a rotation logger writer
func getRotationLogger(engineDir, logFolderPath string, IsRelativePathFlag bool, logRotationNumberFiles,
	logRotationMaxSize, logRotationMaxNumberDays int, logPrefix, LogExtension string) io.Writer {

	logFileName := getLogFileName(logPrefix, LogExtension)
	var logFilesPath string

	if IsRelativePathFlag {
		logFilesPath = path.Join(engineDir, logFolderPath, logFileName)
	} else {
		logFilesPath = path.Join(logFolderPath, logFileName)
	}

	rollLogWritter := &lumberjack.Logger{
		Filename:   logFilesPath,
		MaxBackups: logRotationNumberFiles,   // files
		MaxSize:    logRotationMaxSize,       // megabytes
		MaxAge:     logRotationMaxNumberDays, // days
	}

	return rollLogWritter
}

// function to initialise the logging according to the configuration loaded,
//it returns the log file to be closed at the end of the execution
func InitLogging(loggingLevel, loggingMode, engineDir, logFolderPath, logPrefix, logExtension string, myAsyncLogsFlag,
	consoleHumanFriendlyFlag, IsRelativePathFlag bool, logRotationMaxSize, logRotationNumberFiles,
	logRotationMaxNumberDays int, logRotationCompress, showCaller bool) *os.File {
	// https://medium.com/swlh/stop-using-prints-and-embrace-zerolog-2c4dd8e8816a
	// https://gist.github.com/panta/2530672ca641d953ae452ecb5ef79d7d#file-logging-go-L77
	// https://gist.github.com/panta/2530672ca641d953ae452ecb5ef79d7d

	//variable to return
	var logFile *os.File
	// -------------------------------
	// logging level
	// -------------------------------
	switch strings.ToUpper(loggingLevel) {
	case consLogLevelTrace:
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case consLogLevelDebug:
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case consLevelWarn:
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case consLogLevelError:
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// -------------------------------
	// update the operation flags of
	// the logger (if applicable):
	// - async log flag
	// -------------------------------
	if myAsyncLogsFlag {
		asyncLogsFlag = true
	}

	// -------------------------------
	// configuring the logger output
	// -------------------------------

	// engine logger to configure as wanted
	engineLogger := log.Logger

	// logging mode
	switch strings.ToUpper(loggingMode) {

	case consLogModeBoth:
		//outpout -> console & file
		//projectDir, logFolderPath string, IsRelativePathFlag bool
		logFile, err := getLogFile(engineDir, logFolderPath, IsRelativePathFlag, logPrefix, logExtension)
		var multi zerolog.LevelWriter
		if err != nil {
			log.Error().Err(err).Msg("error creating the log file, only using console log")
		} else {
			log.Debug().Msg("Log file created correctly")
			if consoleHumanFriendlyFlag {
				consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout}
				multi = zerolog.MultiLevelWriter(consoleWriter, logFile)
			} else {
				multi = zerolog.MultiLevelWriter(os.Stdout, logFile)
			}

			if showCaller {
				engineLogger = zerolog.New(multi).With().Timestamp().Logger().With().Caller().Logger()
			} else {
				engineLogger = zerolog.New(multi).With().Timestamp().Logger()
			}
		}

	case consLogModeFile:
		//outpout -> file
		logFile, err := getLogFile(engineDir, logFolderPath, IsRelativePathFlag, logPrefix, logExtension)
		if err != nil {
			log.Error().Err(err).Msg("error creating the log file, only using console log")
		} else {
			log.Debug().Msg("Log file created correctly")

			if showCaller {
				engineLogger = zerolog.New(logFile).With().Timestamp().Logger().With().Caller().Logger()
			} else {
				engineLogger = zerolog.New(logFile).With().Timestamp().Logger()
			}
		}

	case consLogModeFileRotating:
		//outpout -> file + log rotation
		rollLogWritter := getRotationLogger(engineDir, logFolderPath, IsRelativePathFlag,
			logRotationNumberFiles, logRotationMaxSize, logRotationMaxNumberDays,
			logPrefix, logExtension)

		if showCaller {
			engineLogger = zerolog.New(rollLogWritter).With().Timestamp().Logger().With().Caller().Logger()
		} else {
			engineLogger = zerolog.New(rollLogWritter).With().Timestamp().Logger()
		}

	case consLogModeBothRotating:
		//outpout -> console & file + log rotation
		var multi zerolog.LevelWriter
		rollLogWritter := getRotationLogger(engineDir, logFolderPath, IsRelativePathFlag,
			logRotationNumberFiles, logRotationMaxSize, logRotationMaxNumberDays,
			logPrefix, logExtension)
		if consoleHumanFriendlyFlag {
			consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout}
			multi = zerolog.MultiLevelWriter(consoleWriter, rollLogWritter)
		} else {
			multi = zerolog.MultiLevelWriter(os.Stdout, rollLogWritter)
		}

		if showCaller {
			engineLogger = zerolog.New(multi).With().Timestamp().Logger().With().Caller().Logger()
		} else {
			engineLogger = zerolog.New(multi).With().Timestamp().Logger()
		}

	default:
		//outpout -> console
		if consoleHumanFriendlyFlag {
			if showCaller {
				engineLogger = log.Output(
					zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Logger().With().Caller().Logger()
			} else {
				engineLogger = log.Output(
					zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Logger()
			}
		}
	}
	// put the engine loggger configured as wanted, as the main logger of the system
	log.Logger = engineLogger
	return logFile
}

// -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// LOGGING CUSTOM THREAD SAFE FUNCTIONS
// -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

func FatalLog(message string, err error) {

	logMutex.Lock()
	// ---------------------------------
	// Thread safe space
	if err != nil {
		log.Fatal().Msg(message)
	} else {
		log.Fatal().Err(err).Msg(message)
	}
	// ---------------------------------
	logMutex.Unlock()
}

// -----------------------------------------------------
// Error Log:
// It is the error log from zerolog + thread safe
// mechanism (locks)
// -----------------------------------------------------
func errorLogLogic(message string, err error) {

	logMutex.Lock()
	// ---------------------------------
	// Thread safe space
	if err != nil {
		log.Error().Err(err).Msg(message)

	} else {
		log.Error().Msg(message)
	}
	// ---------------------------------
	logMutex.Unlock()
}

func ErrorLog(message string, err error) {

	if asyncLogsFlag {
		//do the logging action in a different thread
		go errorLogLogic(message, err)

	} else {
		errorLogLogic(message, err)
	}
}

// -----------------------------------------------------
// Warn Log:
// It is the Warn log from zerolog + thread safe
// mechanism (locks)
// -----------------------------------------------------

func warnLogLogic(message string, err error) {

	logMutex.Lock()
	// ---------------------------------
	// Thread safe space
	if err != nil {
		log.Warn().Msg(message)

	} else {
		log.Warn().Err(err).Msg(message)
	}
	// ---------------------------------
	logMutex.Unlock()
}

func WarnLog(message string, err error) {

	if asyncLogsFlag {
		//do the logging action in a different thread
		go warnLogLogic(message, err)

	} else {
		warnLogLogic(message, err)
	}
}

// -----------------------------------------------------
// Info Log:
// It is the Info log from zerolog + thread safe
// mechanism (locks)
// -----------------------------------------------------

func infoLogLogic(message string, err error) {

	logMutex.Lock()
	// ---------------------------------
	// Thread safe space
	if err != nil {
		log.Info().Msg(message)

	} else {
		log.Info().Err(err).Msg(message)
	}
	// ---------------------------------
	logMutex.Unlock()
}

func InfoLog(message string, err error) {

	if asyncLogsFlag {
		//do the logging action in a different thread
		go infoLogLogic(message, err)

	} else {
		infoLogLogic(message, err)
	}
}

// -----------------------------------------------------
// Debug Log:
// It is the Debug log from zerolog + thread safe
// mechanism (locks)
// -----------------------------------------------------

func debugLogLogic(message string, err error) {

	logMutex.Lock()
	// ---------------------------------
	// Thread safe space
	if err != nil {
		log.Debug().Msg(message)

	} else {
		log.Debug().Err(err).Msg(message)
	}
	// ---------------------------------
	logMutex.Unlock()
}

func DebugLog(message string, err error) {

	if asyncLogsFlag {
		//do the logging action in a different thread
		go debugLogLogic(message, err)

	} else {
		debugLogLogic(message, err)
	}
}

// -----------------------------------------------------
// External Activity Log:
// function to be used for informing about external activity via Logs
// it is the info log from zero log + some flag + thread safe mechanism (locks)
// -----------------------------------------------------

func externalActivityLogLogic(message string) {

	logMutex.Lock()
	// ---------------------------------
	// Thread safe space
	log.Info().Bool(consExternalActivityLogKey, true).Msg(message)
	// ---------------------------------
	logMutex.Unlock()
}

func ExternalActivityLog(message string) {

	if asyncLogsFlag {
		//do the logging action in a different thread
		go externalActivityLogLogic(message)

	} else {
		externalActivityLogLogic(message)
	}
}
