/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - main.go
=================================================
Author: Alberto Dominguez

This software artefact manages the external connector modules, geting information about
their activity and sending orders to them (if any). This go packages loads
the configuration file and initilizes the main variables (context and logger).
*/

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"

	"sec-lope-de-vega/internal/cockpit"
	"sec-lope-de-vega/internal/englogging"
	"sec-lope-de-vega/internal/opvariables"
)

// constants
const (
	// execution environment
	consFlagEnv                  = "env"
	consFlagBanner               = "nobanner"
	consFlagConfig               = "config"
	consDevEnv                   = "DEV"
	consProEnv                   = "PRO"
	consCommandExplanationExcEnv = "Execution environment of Sec Lope de Vega engine"
	consCommandExplanationBanner = "Flag for hiding the banner"
	consCommandExplanationConfig = "Config file to use"
	// configuration files
	consConfigFolder = "config"
	consConfigFile   = "engine_config.yml"
)

// function to load the configuration file and create
// a config struct by parsing the yml file. It also
// returns the root path of the project and the path of the conversation rules
// https://dev.to/ilyakaznacheev/a-clean-way-to-pass-configs-in-a-go-application-1g64
func loadConfigFiles(exEnvPtr, configFilePathParameter *string) (*opvariables.Config, string) {
	var engineDir string
	config := opvariables.Config{}
	// get current directory
	wd, err := os.Getwd()
	if err != nil {
		log.Fatal().Err(err).Msg("Error getting the current working directory, ending execution")
	}
	// defining the execution environment
	if *exEnvPtr == consDevEnv {
		// DEV environment
		engineDir = filepath.Dir(wd)
	} else {
		// PRO environment
		engineDir = wd
	}
	fmt.Println("Detected Working Directory: '" + engineDir + "'")

	var file *os.File
	//open configuration file
	if len(*configFilePathParameter) == 0 {
		file, err = os.Open(filepath.Join(engineDir, consConfigFolder, consConfigFile))
	} else {
		file, err = os.Open(*configFilePathParameter)
	}

	if err != nil {
		log.Fatal().Err(err).Msg("Error loading the configuration file, ending execution")
	} else {
		defer file.Close()
	}
	//parsing config file and put the results in the struct (object)
	err = yaml.NewDecoder(file).Decode(&config)

	if err != nil {
		log.Fatal().Err(err).Msg("Error parsing the configuration file, ending execution")
	}
	return &config, engineDir
}

// function to print the banner in the terminal
// http://patorjk.com/
func banner() {
	fmt.Println("***************************************************************************************************************************************************************************************")
	fmt.Println("")
	fmt.Println("***************************************************************************************************************************************************************************************")
	fmt.Println("")
	fmt.Println("      *******                                 ***** *                                                ***** **                      ***** *      **                                      ")
	fmt.Println("    *       ***                            ******  *                                              ******  ***                   ******  *    *****                                      ")
	fmt.Println("   *         **                           **   *  *                                             **    *  * ***                 **   *  *       *****                                    ")
	fmt.Println("   **        *                           *    *  *                                             *     *  *   ***               *    *  **       * **                                     ")
	fmt.Println("    ***                                      *  *              ****       ****                      *  *     ***                  *  ***      *                                         ")
	fmt.Println("   ** ***           ***       ****          ** **             * ***  *   * ***  *    ***           ** **      **    ***          **   **      *         ***        ****         ****    ")
	fmt.Println("    *** ***        * ***     * ***  *       ** **            *   ****   *   ****    * ***          ** **      **   * ***         **   **      *        * ***      *  ***  *    * ***  * ")
	fmt.Println("      *** ***     *   ***   *   ****        ** **           **    **   **    **    *   ***         ** **      **  *   ***        **   **     *        *   ***    *    ****    *   ****  ")
	fmt.Println("        *** ***  **    *** **               ** **           **    **   **    **   **    ***        ** **      ** **    ***       **   **     *       **    ***  **     **    **    **   ")
	fmt.Println("           ** ** *******   **               *  **           **    **   **    **   *******          *  **      ** *******          **  **    *        *******    **     **    **    **   ")
	fmt.Println("            * *  **        **                  *            **    **   **    **   **                  *       *  **                ** *     *        **         **     **    **    **   ")
	fmt.Println("  ***        *   ****    * ***     *       ****           *  ******    *******    ****    *      *****       *   ****    *          ***     *        ****    *  **     **    **    **   ")
	fmt.Println(" *  *********     *******   *******       *  *************    ****     ******      *******      *   *********     *******            *******          *******    ********     ***** **  ")
	fmt.Println("*                                        *                             **                      *                                                                        ***             ")
	fmt.Println(" **                                       **                           **                       **                                                                ****   ***            ")
	fmt.Println("                                                                                                                                                               *     ****               ")
	fmt.Println("")
	fmt.Println("")
	fmt.Println("")
	fmt.Println("     ***** **                                                                                                                                                                           ")
	fmt.Println("  ******  **** *                              *                                                                                                                                         ")
	fmt.Println(" **   *  * ****                              ***                                                                                                                                        ")
	fmt.Println("*    *  *   **                                *                                                                                                                                         ")
	fmt.Println("    *  *                                                                                                                                                                                ")
	fmt.Println("   ** **         ***  ****        ****      ***     ***  ****       ***                                                                                                                 ")
	fmt.Println("   ** **          **** **** *    *  ***  *   ***     **** **** *   * ***                                                                                                                ")
	fmt.Println("   ** ******       **   ****    *    ****     **      **   ****   *   ***                                                                                                               ")
	fmt.Println("   ** *****        **    **    **     **      **      **    **   **    ***                                                                                                              ")
	fmt.Println("   ** **           **    **    **     **      **      **    **   ********                                                                                                               ")
	fmt.Println("   *  **           **    **    **     **      **      **    **   *******                                                                                                                ")
	fmt.Println("      *            **    **    **     **      **      **    **   **                                                                                                                     ")
	fmt.Println("  ****         *   **    **    **     **      **      **    **   ****    *                                                                                                              ")
	fmt.Println(" *  ***********    ***   ***    ********      *** *   ***   ***   *******                                                                                                               ")
	fmt.Println("*     ******        ***   ***     *** ***      ***     ***   ***   *****                                                                                                                ")
	fmt.Println("*                                      ***                                                                                                                                              ")
	fmt.Println(" **                              ****   ***                                                                                                                                             ")
	fmt.Println("                               *******  **                                                                                                                                              ")
	fmt.Println("                              *     ****                                                                                                                                                ")
	fmt.Println("")
	fmt.Println("***************************************************************************************************************************************************************************************")
	fmt.Println("")
	fmt.Println("***************************************************************************************************************************************************************************************")
	fmt.Println("VERSION: 0.5")
	fmt.Println("")
	fmt.Println("")
	fmt.Println("STARTING EXECUTION...")
}

// ======================================================================================
// STARTING POINT
// ======================================================================================
func main() {

	// OS args
	// https://gobyexample.com/command-line-flags
	exEnvPtr := flag.String(consFlagEnv, consProEnv, consCommandExplanationExcEnv)
	configFilePathParameter := flag.String(consFlagConfig, "", consCommandExplanationConfig)
	bannerFlagPtr := flag.Bool(consFlagBanner, true, consCommandExplanationBanner)
	flag.Parse()
	if *bannerFlagPtr {
		//printing welcome banner
		banner()
	}
	// loading the configuration file
	config, engineDir := loadConfigFiles(exEnvPtr, configFilePathParameter)
	// initialise log
	logFile := englogging.InitLogging(
		config.Logging.Level,
		config.Logging.Mode, engineDir,
		config.Logging.LogFolder.Path,
		config.Logging.LogPrefix,
		config.Logging.LogExtension,
		config.Logging.AsyncLogs,
		config.Logging.ConsoleHumanFriendly,
		config.Logging.LogFolder.IsRelativePath,
		config.Logging.LogRotationMaxSize,
		config.Logging.LogRotationNumberFiles,
		config.Logging.LogRotationMaxNumberDays,
		config.Logging.LogRotationCompress,
		config.Logging.ShowCaller,
	)

	//prepare log file closing order at the time engine stops
	defer logFile.Close()
	// creating the context object
	ctx := opvariables.NewContext(config, engineDir)
	// starting the engine
	cockpit.StartEngine(ctx)
}
