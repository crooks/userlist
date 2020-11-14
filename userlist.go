package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crooks/sshcmds"
)

type hostsInfo struct {
	hostFile  string
	hostNames []string
	users     map[string]map[string]userInfo
	allUsers  []string
}

type userInfo struct {
	uid    int
	passwd string
	name   string
	shell  string
	last   time.Time
	pwchg  time.Time
	hash   string
}

// newUser returns a partially populated userInfo struct
func newUser(uid int, passwd, name, shell string) *userInfo {
	return &userInfo{
		uid:    uid,
		passwd: passwd,
		name:   name,
		shell:  shell,
	}
}

// newHosts returns a partially populated hostsInfo struct
func newHosts(hostFile string) *hostsInfo {
	return &hostsInfo{
		hostFile: hostFile,
		users:    make(map[string]map[string]userInfo),
	}
}

// stringInSlice returns true if string(s) is a member of slice(list).
func stringInSlice(s string, list []string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// stringToEpoch takes a string of days since Epoch and converts it to a Unix
// time object.  Note: The Epoch object is in seconds so the return needs to be
// multiplied by the number of seconds per day.
func stringToEpoch(s string) (time.Time, error) {
	days, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(days*3600*24, 0), nil
}

// parsePasswd extracts the required fields from the /etc/passwd file and
// populates a userInfo map for each line in it.  Note: This function
// initialises a users struct for each user found.  Subsequent functions will
// only populate fields in existing user structs.
func (h *hostsInfo) parsePasswd(hostName string, b bytes.Buffer) {
	unwantedShells := []string{"nologin", "false", "sync", "shutdown", "halt"}
	if h.users[hostName] == nil {
		h.users[hostName] = map[string]userInfo{}
	}
	// Iterate over each line in the passwd file
	for _, line := range strings.Split(b.String(), "\n") {
		fields := strings.Split(line, ":")
		userName := fields[0]
		// Ignore lines that don't have sufficient fields to include a
		// shell
		if len(fields) < 7 {
			continue
		}
		shell := fields[6]
		// Skip users with an unwanted shell
		shellWords := strings.Split(shell, "/")
		shellName := shellWords[len(shellWords)-1]
		if stringInSlice(shellName, unwantedShells) {
			Trace.Printf(
				"Skipping unwanted shell: host=%s, user=%s, shell=%s",
				hostName,
				userName,
				fields[6],
			)
			continue
		}
		// At this time, the linux passwd field should be either empty or "x".
		passwd := fields[1]
		// Convert the uid field to an integer
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			Warn.Printf("%s: UID cannot be converted to integer", fields[2])
			continue
		}
		// Make a (hopefully not too bold) choice that the first (CSV)
		// comment field is the user's real name.
		name := strings.Split(fields[4], ",")[0]
		h.users[hostName][userName] = *newUser(uid, passwd, name, shell)
		if !stringInSlice(userName, h.allUsers) {
			h.allUsers = append(h.allUsers, userName)
		}
	}
}

// parseShadow iterates each line of the /etc/shadow file and extracts the
// fields required for each user.
func (h *hostsInfo) parseShadow(hostName string, b bytes.Buffer) {
	for _, line := range strings.Split(b.String(), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		user := fields[0]

		// Field 1 is the password hash.  A prefix of $6$ indicates the hash is
		// type SHA512.  The following table is fairly self-explanitory.
		var hash string
		if strings.HasPrefix(fields[1], "$6$") {
			hash = "sha512"
		} else if strings.HasPrefix(fields[1], "$5$") {
			hash = "sha256"
		} else if strings.HasPrefix(fields[1], "$1$") {
			hash = "md5"
		} else if strings.HasPrefix(fields[1], "!") {
			hash = "N/A"
		} else if strings.HasPrefix(fields[1], "*") {
			hash = "N/A"
		} else if len(fields[1]) == 13 {
			hash = "expired"
		} else if len(fields[1]) == 0 {
			hash = "blank"
		} else {
			hash = "unknown"
		}

		// Attempt to convert the third field to a Unix Epoch time
		pwchg, err := stringToEpoch(fields[2])
		if err != nil {
			Warn.Printf(
				"Hostname=%s, User=%s: Unable to parse Epoch of: %s",
				hostName,
				user,
				fields[2],
			)
		}
		// We're only populating fields of known user accounts.  During
		// /etc/passwd parsing, accounts with unwanted shells were excluded so
		// it's not unexpected that there will be unwanted users in
		// /etc/shadow.
		_, exists := h.users[hostName][user]
		if exists {
			u := h.users[hostName][user]
			u.pwchg = pwchg
			u.hash = hash
			h.users[hostName][user] = u
		}
	}
}

// setLast converts a date string to a Time.  If the date is more recent than
// the previous most recent for a given user, the last date for that user is
// updated.
func (u *userInfo) setLast(s string) {
	lastdate, err := time.Parse("Jan 2 15:04:05 2006", s)
	if err != nil {
		panic(err)
	}
	if lastdate.After(u.last) {
		u.last = lastdate
	}
}

// parseLast iterates through the lines returned by the "last" command.  This
// code is written for Red Hat which has a primitive output compared to other
// Linux flavours.
func (h *hostsInfo) parseLast(hostName string, b bytes.Buffer) {
	for _, line := range strings.Split(b.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		user := fields[0]
		_, exists := h.users[hostName][user]
		if exists {
			u := h.users[hostName][user]
			//u.setLast(fields[2])
			u.setLast(strings.Join(fields[3:7], " "))
			h.users[hostName][user] = u
		}
	}
	return
}

// readHostNames iterates over file containing hostnames and populates a list.
func (h *hostsInfo) readHostNames(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal("Unable to open " + err.Error())
	}
	defer file.Close()
	h.hostFile = filename
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		h.hostNames = append(h.hostNames, scanner.Text())
	}
	Info.Printf("Read %d hostnames from %s", len(h.hostNames), filename)
}

// writeToFile exports the map of hosts/users to a CSV file.
func (h *hostsInfo) writeToFile(filename string) {
	f, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Unable to write output: %s", err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)

	// Create a list of map keys and sort them.  This enables the output to be
	// alphanumerically sorted by hostname.
	keys := make([]string, 0, len(h.users))
	for k := range h.users {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var datestr string
	var pwchg string
	dateThreshold := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	// Iterate over the sorted hostnames
	//w.WriteString("host,user,uid,passwd,name,shell,lastlogin,pwhash,pwchanged\n")
	for _, host := range keys {
		for _, u := range h.allUsers {
			info, exists := h.users[host][u]
			if exists {
				pwchg = info.pwchg.Format("2006-01-02")
				if info.last.After(dateThreshold) {
					datestr = info.last.Format("2006-01-02")
				} else {
					datestr = ""
				}
				line := fmt.Sprintf(
					"%s,%s,%d,%s,%s,%s,%s,%s,%s\n",
					host, u, info.uid, info.passwd, info.name, info.shell,
					datestr, info.hash, pwchg,
				)
				w.WriteString(line)
			}
		}
	}
	w.Flush()
}

func main() {
	var err error
	// Reading the config has to happen first.  It determines the loglevel and
	// logpath.
	setCfg()
	// Attempt to open the logfile, check it for errors and defer its closure.
	logfile, err := os.OpenFile(
		cfg.LogFile,
		os.O_RDWR|os.O_CREATE|os.O_APPEND,
		0640,
	)
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"Error opening logfile: %s.\n",
			err,
		)
		os.Exit(1)
	}
	defer logfile.Close()
	// Initialize logging with our desired log levels.
	switch strings.ToLower(cfg.LogLevel) {
	case "trace":
		logInit(logfile, logfile, logfile, logfile)
	case "info":
		logInit(ioutil.Discard, logfile, logfile, logfile)
	case "warn":
		logInit(ioutil.Discard, ioutil.Discard, logfile, logfile)
	case "error":
		logInit(ioutil.Discard, ioutil.Discard, ioutil.Discard, logfile)
	default:
		fmt.Fprintf(
			os.Stderr,
			"Unknown loglevel: %s.  Assuming \"Info\".\n",
			cfg.LogLevel,
		)
		logInit(ioutil.Discard, logfile, logfile, logfile)
	}
	hosts := newHosts(cfg.ServerList)
	hosts.readHostNames(cfg.ServerList)
	var b bytes.Buffer
	sshSession := sshcmds.NewConfig()
	validKeys := 0
	for _, k := range cfg.PrivateKeys {
		err := sshSession.AddKey(cfg.SSHUser, k)
		if err != nil {
			Warn.Printf("%s: %s", k, err)
			continue
		}
		validKeys++
	}
	if validKeys == 0 {
		Error.Println("No valid private keys found")
		os.Exit(1)
	}
	hostsParsed := 0
	totalT0 := time.Now()
	for _, hostName := range hosts.hostNames {
		hostShort := strings.Split(hostName, ".")[0]
		hostT0 := time.Now()
		client, err := sshSession.Auth(hostName)
		b, err = sshSession.Cmd(client, "cat /etc/passwd")
		if err != nil {
			Warn.Printf("%s", err)
			continue
		}
		hosts.parsePasswd(hostShort, b)

		b, err = sshSession.Cmd(client, "sudo cat /etc/shadow")
		if err != nil {
			Warn.Printf("%s", err)
			continue
		}
		hosts.parseShadow(hostShort, b)

		b, err = sshSession.Cmd(client, "last -aF")
		if err != nil {
			Warn.Printf("%s", err)
			continue
		}
		client.Close()
		hosts.parseLast(hostShort, b)
		hostT1 := time.Now()
		hostDuration := hostT1.Sub(hostT0)
		hostsParsed++
		Info.Printf(
			"%s: Parsed in %.2f seconds",
			hostShort,
			hostDuration.Seconds(),
		)
	}
	totalT1 := time.Now()
	totalDuration := totalT1.Sub(totalT0)
	Info.Printf(
		"Successfully parsed %d hosts out of %d in %.1f seconds",
		hostsParsed,
		len(hosts.hostNames),
		totalDuration.Seconds(),
	)

	// Write the gathered user data to a file
	hosts.writeToFile(cfg.OutFileCSV)
}
