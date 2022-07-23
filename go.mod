module github.com/crooks/userlist

go 1.18

require (
	github.com/Masterminds/log-go v1.0.0
	github.com/crooks/jlog v0.0.0-20220722131440-a145743cbde6
	github.com/crooks/sshcmds v0.0.0-20201114194206-3279c632edf8
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf // indirect
	golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d // indirect
	golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 // indirect
)

replace github.com/Masterminds/log-go => github.com/crooks/log-go v0.4.2
