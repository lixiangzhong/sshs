package main

import (
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/urfave/cli/v2"
)

type doctorIssue struct {
	Message string
}

func DoctorAction(c *cli.Context) error {
	cfg, configPath, err := loadConfigFile(configFileList(".sshs.yaml", "sshs.yaml", ".sshw.yaml", "sshw.yaml")...)
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
	hosts := make(map[string][]string)
	collectConfigHosts(hosts, "", cfg)

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

func collectConfigHosts(hosts map[string][]string, prefix string, cfg []Config) {
	for _, item := range cfg {
		name := joinConfigName(prefix, item.Name)
		if len(item.Children) > 0 {
			collectConfigHosts(hosts, name, item.Children)
			continue
		}
		if item.Host == "" {
			continue
		}
		remoteAddr := item.RemoteAddr()
		hosts[remoteAddr] = append(hosts[remoteAddr], name)
	}
}

func joinConfigName(prefix, name string) string {
	if prefix == "" {
		return name
	}
	if name == "" {
		return prefix
	}
	return prefix + "/" + name
}
