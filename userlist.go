package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/log-go"
	"github.com/crooks/jlog"
	"github.com/crooks/sshcmds"
	"github.com/crooks/userlist/config"
)

var (
	cfg   *config.Config
	flags *config.Flags
)

type hostsInfo struct {
	hostNames []string
	users     map[string]map[string]userInfo
	allUsers  []string
	uidMap    map[int][]string
	parsed    int // Number of hosts processed
	success   int // Number of hosts successfully processed
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

// newHosts constructs a new instance of hostsInfo
func newHosts() *hostsInfo {
	return &hostsInfo{
		users:  make(map[string]map[string]userInfo),
		uidMap: make(map[int][]string),
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
			log.Tracef(
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
			log.Warnf("%s: UID cannot be converted to integer", fields[2])
			continue
		}
		// Populate the UID Map
		if !stringInSlice(userName, h.uidMap[uid]) {
			log.Debugf("%d: Adding %s to UID map", uid, userName)
			h.uidMap[uid] = append(h.uidMap[uid], userName)
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
			log.Warnf(
				"Hostname=%s, User=%s, Filename=/etc/shadow: Unable to parse Epoch of: %s",
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
}

// nonBlankName iterates through all known hosts looking for a specified
// userName.  If it finds one, it checks that the corresponding name field in
// the users struct (The comments field in /etc/passwd) is not blank.  If this
// is true, the name is returned as a string.
func (h *hostsInfo) nonBlankName(userName string) string {
	for _, host := range h.hostNames {
		// Test if this host has an entry for the specified userName
		if _, ok := h.users[host][userName]; ok {
			if len(h.users[host][userName].name) > 0 {
				// The userName is good and the name field has some content.
				return h.users[host][userName].name
			}
		}
	}
	// Give up.  Unlikely as it seems, no hits were found.
	return ""
}

// writeMapToFile produces two files.  One of conflicting UIDs and one of
// correct, unique UIDs.
func (h *hostsInfo) writeMapToFile(collisionsCSV, mapCSV string) {
	// Create and open the UID Collisions file
	csvc, err := os.Create(collisionsCSV)
	if err != nil {
		log.Fatalf("Unable to write collisionsCSV: %s", err)
	}
	defer csvc.Close()
	bufc := bufio.NewWriter(csvc)
	// Create and open the UID Map file
	csvm, err := os.Create(mapCSV)
	if err != nil {
		log.Fatalf("Unable to write mapCSV: %s", err)
	}
	defer csvm.Close()
	bufm := bufio.NewWriter(csvm)
	// Create a slice of uid keys for sorting purposes
	keys := make([]int, 0, len(h.uidMap))
	for k := range h.uidMap {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	// Iterate through all the discovered UIDs.  If there is >1 associated
	// userNames, write the UID to file.
	for _, uid := range keys {
		if len(h.uidMap[uid]) > 1 {
			// UID collisions
			line := fmt.Sprintf("%d,%s\n", uid, strings.Join(h.uidMap[uid], ","))
			bufc.WriteString(line)
		} else {
			// Good UIDs
			userName := h.uidMap[uid][0]
			line := fmt.Sprintf("%d,%s,%s\n", uid, userName, h.nonBlankName(userName))
			bufm.WriteString(line)
		}
	}
	bufc.Flush()
	bufm.Flush()
}

// writeToFile exports the map of hosts/users to a CSV file.
func (h *hostsInfo) writeToFile(filename string) {
	f, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Unable to write OutFileCSV: %s", err)
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

// readPrivateKeys takes a slice of filenames relating to SSH private key files.
// It returns an instance of sshcmds populated with valid private keys.
func readPrivateKeys(keyFileNames []string) *sshcmds.Config {
	sshSession := sshcmds.NewConfig()
	validKeys := 0
	for _, k := range keyFileNames {
		err := sshSession.AddKey(cfg.SSHUser, k)
		if err != nil {
			log.Warnf("%s: %s", k, err)
			continue
		}
		log.Infof("Imported private key from %s", k)
		validKeys++
	}
	if validKeys > 0 {
		log.Infof("Successfully imported %d private keys", validKeys)
	} else {
		log.Fatal("No valid private keys found")
	}
	return sshSession
}

func (hosts *hostsInfo) parseHost(hostName string, sshcfg sshcmds.Config) {
	hosts.parsed++
	hostShort := strings.Split(hostName, ".")[0]
	log.Infof("Processing host: %s", hostShort)
	hostT0 := time.Now()
	client, err := sshcfg.Auth(hostShort)
	if err != nil {
		log.Warnf("%s: SSH authentication returned: %s", hostName, err)
		return
	}
	defer client.Close()
	var b bytes.Buffer
	b, err = sshcfg.Cmd(client, "cat /etc/passwd")
	if err != nil {
		log.Warnf("%s: Unable to parse /etc/passwd: %v", hostName, err)
		return
	}
	hosts.parsePasswd(hostShort, b)

	b, err = sshcfg.Cmd(client, "sudo cat /etc/shadow")
	if err != nil {
		log.Infof("%s: Cannot parse /etc/shadow: %v", hostName, err)
	} else {
		hosts.parseShadow(hostShort, b)
	}

	b, err = sshcfg.Cmd(client, "last -aF")
	if err != nil {
		log.Infof("%s: Unable to run \"last\" command: %v", hostName, err)
	} else {
		hosts.parseLast(hostShort, b)
	}

	hostT1 := time.Now()
	hostDuration := hostT1.Sub(hostT0)
	hosts.success++
	log.Debugf(
		"%s: Parsed in %.2f seconds",
		hostShort,
		hostDuration.Seconds(),
	)
}

func (hosts *hostsInfo) parseSources() {
	// Create an sshSession and import Private keys into it.
	sshSession := readPrivateKeys(cfg.PrivateKeys)

	// Iterate over a list of URLs that contain hostnames
	for _, s := range cfg.Sources.URLs {
		url, err := http.Get(s)
		if err != nil {
			log.Warnf("Error parsing URL %s: %v", s, err)
			continue
		}
		defer url.Body.Close()
		scanner := bufio.NewScanner(url.Body)
		// Iterate over the lines within a given URL
		for scanner.Scan() {
			hosts.parseHost(scanner.Text(), *sshSession)
		}
	}
	// Iterate over a list of files that contain hostnames
	for _, s := range cfg.Sources.Files {
		f, err := os.Open(s)
		if err != nil {
			log.Warnf("Error parsing file %s: %v", s, err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		// Iterate over the lines within a given file
		for scanner.Scan() {
			hosts.parseHost(scanner.Text(), *sshSession)
		}
	}
	// Iterate over a simple list of hostnames
	for _, s := range cfg.Sources.Servers {
		hosts.parseHost(s, *sshSession)
	}
}

func main() {
	var err error
	// Reading the config has to happen first.  It determines the loglevel and
	// logpath.
	flags = config.ParseFlags()
	cfg, err = config.ParseConfig(flags.Config)
	if err != nil {
		log.Fatalf("Unable to parse config: %v", err)
	}
	// With a config in place, logging can now be configured.
	loglevel, err := log.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Fatalf("Unable to parse log level: %v", err)
	}
	log.Current = jlog.NewJournal(loglevel)

	// Create a new instance of hostsInfo
	hosts := newHosts()

	totalT0 := time.Now()
	hosts.parseSources()
	totalT1 := time.Now()
	totalDuration := totalT1.Sub(totalT0)
	log.Infof(
		"Successfully parsed %d hosts out of %d in %.1f seconds",
		hosts.success,
		hosts.parsed,
		totalDuration.Seconds(),
	)

	// Write the gathered user data to a file
	hosts.writeToFile(cfg.OutFileCSV)
	hosts.writeMapToFile(cfg.CollisionsCSV, cfg.UIDMapCSV)
}
