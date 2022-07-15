package config

import (
	"errors"
	"flag"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

type Flags struct {
	Config string
}

//Config contains the userlist configuration options
type Config struct {
	CollisionsCSV string   `yaml:"collisions_file"`
	LogFile       string   `yaml:"logfile"`
	LogLevel      string   `yaml:"loglevel"`
	OutFileCSV    string   `yaml:"out_file"`
	PrivateKeys   []string `yaml:"private_keys"`
	ServerList    string   `yaml:"server_list"`
	SSHTimeout    string   `yaml:"ssh_timeout"`
	SSHUser       string   `yaml:"ssh_user"`
	UIDMapCSV     string   `yaml:"uidmap_file"`
}

func ParseConfig(filename string) (*Config, error) {
	config := new(Config)
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	d := yaml.NewDecoder(file)
	if err := d.Decode(&config); err != nil {
		return nil, err
	}
	// We can safely make a guess at some config options
	if config.LogLevel == "" {
		config.LogLevel = "info"
	}
	if config.SSHTimeout == "" {
		config.SSHTimeout = "10s"
	}
	if config.CollisionsCSV == "" {
		config.CollisionsCSV = "uid_conflict.csv"
	}
	if config.OutFileCSV == "" {
		config.OutFileCSV = "userlist.csv"
	}
	if config.UIDMapCSV == "" {
		config.UIDMapCSV = "uid_map.csv"
	}
	// Allow for tilde expansion on these config options
	config.CollisionsCSV = expandTilde(config.CollisionsCSV)
	config.OutFileCSV = expandTilde(config.OutFileCSV)
	config.UIDMapCSV = expandTilde(config.UIDMapCSV)
	// Others cannot be guessed and must be user defined
	if config.ServerList == "" {
		return nil, errors.New("server_list is not defined")
	}
	if config.SSHUser == "" {
		return nil, errors.New("ssh_user is not defined")
	}
	// Check if the various output files are writable.  It's much less overhead
	// to find out now instead of during post-processing.
	err = touchAndDel(config.CollisionsCSV)
	if err != nil {
		return nil, err
	}
	err = touchAndDel(config.OutFileCSV)
	if err != nil {
		return nil, err
	}
	err = touchAndDel(config.UIDMapCSV)
	if err != nil {
		return nil, err
	}
	// Iterate over the given Private keys and expand tildes
	for n := range config.PrivateKeys {
		config.PrivateKeys[n] = expandTilde(config.PrivateKeys[n])
	}
	return config, nil
}

// touchAndDel creates and then removes a file.  This is a quick and dirty test
// to see if a given filename can be written.
func touchAndDel(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	file.Close()
	defer os.Remove(filename)
	return nil
}

// parseFlags processes arguments passed on the command line in the format
// standard format: --foo=bar
func ParseFlags() *Flags {
	f := new(Flags)
	flag.StringVar(&f.Config, "config", "userlist.yml", "Path to userlist configuration file")
	flag.Parse()
	return f
}

// WriteConfig will create a YAML formatted config file from a Config struct
func (c *Config) WriteConfig(filename string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

// expandTilde expands filenames and paths that use the tilde convention to imply relative to homedir.
func expandTilde(inPath string) (outPath string) {
	u, err := user.Current()
	if err != nil {
		panic(err)
	}
	if inPath == "~" {
		outPath = u.HomeDir
	} else if strings.HasPrefix(inPath, "~/") {
		outPath = path.Join(u.HomeDir, inPath[2:])
	} else {
		outPath = inPath
	}
	return
}
