package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/urfave/cli/v2"
)

type doctorIssue struct {
	Message string
}

func DoctorAction(c *cli.Context) error {
	cfg, configPath, err := loadConfigFile(configFileList(configFilenames...)...)
	if err != nil {
		return cli.Exit(fmt.Sprintf("config: %v", err), 1)
	}

	writer := doctorWriter(c)
	fmt.Fprintf(writer, "config file: %s\n", configPath)
	issues := checkDoctorIssues(cfg)
	if len(issues) == 0 {
		fmt.Fprintln(writer, "status: ok")
		return nil
	}

	fmt.Fprintln(writer, "status: issue found")
	for _, issue := range issues {
		fmt.Fprintf(writer, "- %s\n", issue.Message)
	}
	return cli.Exit("doctor found issues", 1)
}

func doctorWriter(c *cli.Context) io.Writer {
	if c == nil || c.App == nil || c.App.Writer == nil {
		return os.Stdout
	}
	return c.App.Writer
}

func checkDoctorIssues(cfg []Config) []doctorIssue {
	flatHosts := filter_unfolding(cfg, "")
	hosts := make(map[string][]string)
	for _, h := range flatHosts {
		if h.Host == "" {
			continue
		}
		name := strings.TrimPrefix(h.Name, "/")
		remoteAddr := h.RemoteAddr()
		hosts[remoteAddr] = append(hosts[remoteAddr], name)
	}

	var issues []doctorIssue
	remoteAddrs := make([]string, 0, len(hosts))
	for remoteAddr := range hosts {
		remoteAddrs = append(remoteAddrs, remoteAddr)
	}
	sort.Strings(remoteAddrs)
	for _, remoteAddr := range remoteAddrs {
		names := hosts[remoteAddr]
		if len(names) <= 1 {
			continue
		}
		issues = append(issues, doctorIssue{
			Message: fmt.Sprintf("duplicate host %s in %v", remoteAddr, names),
		})
	}
	return issues
}
