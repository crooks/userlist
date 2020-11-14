package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"path"

	"github.com/BurntSushi/toml"
)

var (
	// Trace loglevel
	Trace *log.Logger
	// Info loglevel
	Info *log.Logger
	// Warn loglevel
	Warn *log.Logger
	// Error loglevel
	Error *log.Logger // Loglevel Error
)

// Config contains the configuration variables
type Config struct {
	LogFile     string
	LogLevel    string
	OutFileCSV  string
	PrivateKeys []string
	ServerList  string
	SSHTimeout  string
	SSHUser     string
}

// logInit creates the log handlers we want for old-school sensible logging.
func logInit(
	traceHandle io.Writer,
	infoHandle io.Writer,
	warnHandle io.Writer,
	errorHandle io.Writer) {

	Trace = log.New(traceHandle,
		"Trace: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Info = log.New(infoHandle,
		"Info: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Warn = log.New(warnHandle,
		"Warn: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Error = log.New(errorHandle,
		"Error: ",
		log.Ldate|log.Ltime|log.Lshortfile)
}

// Make the cfg struct a global variable
var cfg Config

// fileExists tests for the existence of a file.  Return true if it exists.
func fileExists(filepath string) bool {
	if _, err := os.Stat(filepath); err == nil {
		return true
	} else if os.IsNotExist(err) {
		return false
	} else {
		// Schrodinger: file may of may not exist.  Assume is doesn't as that's
		// the safest option available for a bool return.
		return false
	}
}

// cfgDefaults sets some sane configuration defaults that may or may not be
// sufficient to get things working.
func cfgDefaults(homedir string) {
	progPath := path.Join(homedir, "userlist")
	cfg.LogFile = path.Join(progPath, "userlist.log")
	cfg.LogLevel = "Info"
	cfg.OutFileCSV = path.Join(progPath, "userlist.csv")
	cfg.PrivateKeys = []string{path.Join(homedir, ".ssh", "id_rsa")}
	cfg.ServerList = path.Join(progPath, "servers.txt")
	cfg.SSHTimeout = "10s"
	cfg.SSHUser = "ansible"
}

// setCfg populates the configuration struct called "cfg".
func setCfg() {
	var err error
	userStats, err := user.Current()
	if err != nil {
		fmt.Println("Unable to obtain current user info")
		return
	}
	cfgDefaults(userStats.HomeDir)
	cfgFile := fmt.Sprintf("%s/.userlist.toml", userStats.HomeDir)
	// If the config file exists, read it.  Otherwise, stick with the defaults.
	if fileExists(cfgFile) {
		_, err = toml.DecodeFile(cfgFile, &cfg)
		if err != nil {
			fmt.Printf("Failure reading config: %s\n", err)
			return
		}
	}
}
