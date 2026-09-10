package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func fetch(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func parseClash(data []byte) []string {
	var ipCIDRs []string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ",", 3)
		if len(parts) < 2 {
			continue
		}
		switch parts[0] {
		case "IP-CIDR", "IP-CIDR6":
			ipCIDRs = append(ipCIDRs, strings.TrimSpace(parts[1]))
		}
	}
	return ipCIDRs
}

func loadCustomRules(path string) ([]option.HeadlessRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg option.PlainRuleSetCompat
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	ruleSet, err := cfg.Upgrade()
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return ruleSet.Rules, nil
}

func loadSRS(data []byte) ([]option.HeadlessRule, error) {
	ruleSetCompat, err := srs.Read(bytes.NewReader(data), true)
	if err != nil {
		return nil, err
	}
	ruleSet, err := ruleSetCompat.Upgrade()
	if err != nil {
		return nil, err
	}
	return ruleSet.Rules, nil
}

func writeSRS(outputPath string, rules []option.HeadlessRule) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", outputPath, err)
	}
	defer f.Close()
	if err := srs.Write(f, option.PlainRuleSet{Rules: rules}, C.RuleSetVersionCurrent); err != nil {
		return fmt.Errorf("write srs %s: %w", outputPath, err)
	}
	return nil
}

func main() {
	ruleSetDir := "release"
	for _, dir := range []string{"geoip", "geosite"} {
		if err := os.MkdirAll(filepath.Join(ruleSetDir, dir), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "mkdir", dir+":", err)
			os.Exit(1)
		}
	}

	targets := []string{"direct", "block", "proxy"}
	rules := make(map[string][]option.HeadlessRule, len(targets))
	for _, target := range targets {
		path := "custom-" + target + ".json"
		customRules, err := loadCustomRules(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		rules[target] = customRules
	}

	for _, src := range geoIPSources {
		data, err := fetch(src.url)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}

		if err := writeSRS(filepath.Join(ruleSetDir, src.output), []option.HeadlessRule{{
			Type:           C.RuleTypeDefault,
			DefaultOptions: option.DefaultHeadlessRule{IPCIDR: parseClash(data)},
		}}); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}
	for _, src := range geositeSources {
		data, err := fetch(src.url)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		externalRules, err := loadSRS(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: parse", src.url+":", err)
			os.Exit(1)
		}
		rules[src.target] = append(rules[src.target], externalRules...)
	}

	for _, target := range targets {
		if err := writeSRS(filepath.Join(ruleSetDir, "geosite", "geosite-"+target+".srs"), rules[target]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}
}
