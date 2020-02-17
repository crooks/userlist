package main

import (
	"bufio"
	"bytes"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type hostsInfo struct {
	hostFile  string
	hostNames []string
	users     map[string]map[string]user
	allUsers  []string
}

type user struct {
	uid    int
	passwd int
	name   string
	last   time.Time
}

func newUser(uid, passwd int, name string) *user {
	return &user{
		uid:    uid,
		passwd: passwd,
		name:   name,
	}
}

func newHosts(hostFile string) *hostsInfo {
	return &hostsInfo{
		hostFile: hostFile,
		users:    make(map[string]map[string]user),
	}
}

func stringInSlice(s string, list []string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func (h *hostsInfo) parsePasswd(hostName string, b bytes.Buffer) {
	unwantedShells := []string{"nologin", "false", "sync"}
	if h.users[hostName] == nil {
		h.users[hostName] = map[string]user{}
	}
	for _, line := range strings.Split(b.String(), "\n") {
		fields := strings.Split(line, ":")
		// Ignore lines that don't have sufficient fields to include a
		// shell
		if len(fields) < 7 {
			continue
		}
		// Skip users with an unwanted shell
		shellWords := strings.Split(fields[6], "/")
		shellName := shellWords[len(shellWords)-1]
		if stringInSlice(shellName, unwantedShells) {
			continue
		}
		var passwd int
		// At this time, we only care if a password exists, not what
		// its hash type is.
		if fields[1] == "x" {
			passwd = 1
		} else {
			passwd = 0
		}
		// Convert the uid field to an integer
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			// The UID isn't an integer, do something!
			continue
		}
		// Make a (hopefully not too bold) choice that the first (CSV)
		// comment field is the user's real name.
		name := strings.Split(fields[4], ",")[0]
		id := fields[0]
		h.users[hostName][id] = *newUser(uid, passwd, name)
		if !stringInSlice(id, h.allUsers) {
			h.allUsers = append(h.allUsers, id)
		}
	}
}

func (u *user) setLast(s string) {
	dateiso, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	if dateiso.After(u.last) {
		u.last = dateiso
	}
}

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
			u.setLast(fields[2])
			h.users[hostName][user] = u
		}
	}
	return
}

func privateKeyFile(file string) ssh.AuthMethod {
	key, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil
	}
	return ssh.PublicKeys(signer)
}

func sshClient(hostname string, sshKey ssh.AuthMethod, cmd string) (b bytes.Buffer) {
	// An SSH client is represented with a ClientConn.
	//
	// To authenticate with the remote server you must pass at least one
	// implementation of AuthMethod via the Auth field in ClientConfig,
	// and provide a HostKeyCallback.
	config := &ssh.ClientConfig{
		User: "crooks",
		Auth: []ssh.AuthMethod{
			sshKey,
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	hostport := fmt.Sprintf("%s:22", hostname)
	client, err := ssh.Dial("tcp", hostport, config)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session: ", err)
	}
	defer session.Close()

	// Once a Session is created, you can execute a single command on
	// the remote side using the Run method.
	session.Stdout = &b
	if err := session.Run(cmd); err != nil {
		log.Fatal("Failed to run: " + err.Error())
	}
	return
}

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
}

func htmlHead(w *bufio.Writer) {
	w.WriteString(`<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=us-ascii">
<meta http-equiv="Content-Style-Type" content="text/css2" />
<title>User Accounts</title>
<link rel="stylesheet" type="text/css" href="users.css">
</head>

<body>
`)
}

func (h *hostsInfo) htmlBody(w *bufio.Writer) {
	w.WriteString("<table border=\"1\">\n")

	w.WriteString("<tr><td></td>\n")
	for _, u := range h.allUsers {
		w.WriteString("<th>" + u + "</th>\n")
	}
	w.WriteString("</tr>\n")

	dateThreshold := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	var datestr string
	for host := range h.users {
		w.WriteString("<tr>\n<th>" + host + "</th>\n")
		for _, u := range h.allUsers {
			info, exists := h.users[host][u]
			if exists {
				if info.last.After(dateThreshold) {
					datestr = info.last.Format("2006-01-02")
				} else {
					datestr = "Never"
				}
				w.WriteString("<td>" + datestr)
				w.WriteString("</td>\n")
			} else {
				w.WriteString("<td>N/A</td>\n")
			}
		}
		w.WriteString("</tr>\n")
	}

	w.WriteString("</table>\n")
	w.WriteString("</body>\n")
	w.WriteString("</html>\n")
}

func main() {
	hostFile := "hosts.txt"
	hosts := newHosts(hostFile)
	hosts.readHostNames(hostFile)
	var b bytes.Buffer
	sshKey := privateKeyFile("/home/crooks/.ssh/id_nopass")
	for _, hostname := range hosts.hostNames {
		fmt.Println("Fetching: " + hostname)
		b = sshClient(hostname, sshKey, "cat /etc/passwd")
		hosts.parsePasswd(hostname, b)
		b = sshClient(hostname, sshKey, "last --time-format=iso --nohostname")
		hosts.parseLast(hostname, b)
	}
	fmt.Println(hosts.allUsers)

	f, err := os.Create("users.html")
	if err != nil {
		log.Fatal("Unable to create HTML writer: " + err.Error())
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	htmlHead(w)
	hosts.htmlBody(w)
	w.Flush()

	for host := range hosts.users {
		for _, u := range hosts.allUsers {
			info, exists := hosts.users[host][u]
			if exists {
				fmt.Println(host, u, info.last)
			}
		}
	}
}
