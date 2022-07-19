package config

import (
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
	LogFile     string   `yaml:"logfile"`
	LogLevel    string   `yaml:"loglevel"`
	OutFileCSV  string   `yaml:"outfile"`
	PrivateKeys []string `yaml:"private_keys"`
	ServerList  string   `yaml:"server_list"`
	SSHTimeout  string   `yaml:"ssh_timeout"`
	SSHUser     string   `yaml:"ssh_user"`
}

func NewConfig() *Config {
	progPath := expandTilde("~/userlist")
	return &Config{
		LogFile:    path.Join(progPath, "userlist.log"),
		LogLevel:   "Info",
		OutFileCSV: path.Join(progPath, "userlist.csv"),
		SSHTimeout: "10s",
	}
}

func ParseConfig(filename string) (*Config, error) {
	config := NewConfig()
	if filename != "" {
		file, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		d := yaml.NewDecoder(file)
		if err := d.Decode(&config); err != nil {
			return nil, err
		}
	}
	return config, nil
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
