package main

import (
	"path/filepath"
	"testing"
)

func TestCustomRuleSets(t *testing.T) {
	for _, target := range []string{"direct", "block", "proxy"} {
		t.Run(target, func(t *testing.T) {
			rules, err := loadCustomRules("custom-" + target + ".json")
			if err != nil {
				t.Fatal(err)
			}
			if err := writeSRS(filepath.Join(t.TempDir(), "geosite-"+target+".srs"), rules); err != nil {
				t.Fatal(err)
			}
		})
	}
}
