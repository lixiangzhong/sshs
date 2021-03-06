package main

import (
	"fmt"
	"strings"

	"github.com/manifoldco/promptui"
)

var UItemplates = &promptui.SelectTemplates{
	Label:    "{{ . | cyan}}",
	Active:   "➤ {{ .DisplayName | yellow  }}",
	Inactive: "  {{.DisplayName | faint}} ",
}
var root []Config

func uiSelect(parent, children []Config) (Config, error) {
	ui := promptui.Select{
		Label:        "select",
		Items:        children,
		Size:         15,
		HideSelected: true,
		Templates:    UItemplates,
		Searcher: func(input string, index int) bool {
			root := children[index]
			for _, c := range root.Children {
				if UISearch(c, input, index) {
					return true
				}
			}
			return UISearch(root, input, index)
		},
	}
	index, _, err := ui.Run()
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

func UISearch(c Config, input string, index int) bool {
	content := fmt.Sprintf("%s %s %s", c.Name, c.Username(), c.RemoteAddr())
	return strings.Contains(content, input)
}
