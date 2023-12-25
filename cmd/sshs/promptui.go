package main

import (
	"fmt"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/manifoldco/promptui"
)

var UItemplates = &promptui.SelectTemplates{
	Label:    "{{ . | cyan}}",
	Active:   " ➤ {{. | yellow}}",
	Inactive: "  {{. | faint}}",
}

var root []Config
var selector *promptui.Select

func UISelect(keyword ...string) (Config, error) {
	cfg, err := LoadConfig(keyword...)
	if err != nil {
		return Config{}, err
	}
	if len(cfg) == 1 {
		if len(cfg[0].Children) == 0 && cfg[0].Host != "" {
			return cfg[0], nil
		}
	}
	root = cfg
	return uiSelect(nil, cfg)
}

func uiSelect(parent, children []Config) (Config, error) {
	selector = &promptui.Select{
		Label:        "select",
		Items:        asTableIndentStrings(children),
		Size:         15,
		HideSelected: true,
		Templates:    UItemplates,
		Searcher: func(input string, index int) bool {
			root := children[index]
			for _, c := range root.Children {
				if containKeyword(c, input) {
					return true
				}
			}
			return containKeyword(root, input)
		},
	}
	index, _, err := selector.Run()
	if err != nil {
		return Config{}, err
	}
	backToParent := "◄ back to previous"
	c := children[index]
	if len(c.Children) > 0 { //进入子菜单
		first := c.Children[0]
		if first.Name != backToParent {
			first = Config{Name: backToParent}
			return uiSelect(children, append([]Config{}, append([]Config{first}, c.Children...)...))
		}
		return uiSelect(children, c.Children)
	}
	if c.Name == backToParent {
		if parent == nil {
			return uiSelect(nil, root)
		}
		return uiSelect(nil, parent)
	}
	return c, nil
}

func containKeyword(c Config, keyword ...string) bool {
	content := fmt.Sprintf("%s %s %s", c.Name, c.Username(), c.RemoteAddr())
	for _, v := range keyword {
		if !strings.Contains(content, v) {
			return false
		}
	}
	return true
}

func asTableIndentStrings(cfg []Config) []string {
	t := table.NewWriter()
	t.SetStyle(table.Style{
		Box:     table.StyleBoxDefault,
		Options: table.OptionsNoBordersAndSeparators,
	})
	for _, v := range cfg {
		if len(v.Children) > 0 {
			t.AppendRow(table.Row{v.Name, fmt.Sprintf("(%d Host)", len(v.Children))})
		} else {
			t.AppendRow(table.Row{v.Name, v.Host})
		}
	}
	return strings.Split(t.Render(), "\n")
}
