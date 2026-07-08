package main

import (
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

var upstreamSources = []struct {
	key    string
	url    string
	typ    string // "adguard" or "clash"
	output string
}{
	{
		key:    "telegramnl",
		url:    "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/TelegramNL/TelegramNL.list",
		typ:    "clash",
		output: "geoip/geoip-telegram@nl.srs",
	},
	{
		key:    "telegramsg",
		url:    "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/TelegramSG/TelegramSG.list",
		typ:    "clash",
		output: "geoip/geoip-telegram@sg.srs",
	},
	{
		key:    "telegramus",
		url:    "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/TelegramUS/TelegramUS.list",
		typ:    "clash",
		output: "geoip/geoip-telegram@us.srs",
	},
	{
		key:    "blockhttpdns",
		url:    "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/AdGuard/BlockHttpDNS/BlockHttpDNS.txt",
		typ:    "adguard",
		output: "geosite/geosite-blockhttpdns.srs",
	},
}

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

func parseAdGuard(data []byte) []string {
	var domains []string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}
		line = strings.TrimPrefix(line, "||")
		line = strings.TrimSuffix(line, "^")
		line = strings.TrimSpace(line)
		if line != "" {
			domains = append(domains, "."+line)
		}
	}
	return domains
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

type customRuleConfig struct {
	Version int          `json:"version"`
	Rules   []customRule `json:"rules"`
}

type customRule struct {
	DomainSuffix []string `json:"domain_suffix,omitempty"`
}

func loadCustomRules(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg customRuleConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var suffixes []string
	for _, rule := range cfg.Rules {
		suffixes = append(suffixes, rule.DomainSuffix...)
	}
	return suffixes, nil
}

func writeSRS(outputPath string, headlessRule option.DefaultHeadlessRule) error {
	plainRuleSet := option.PlainRuleSet{
		Rules: []option.HeadlessRule{
			{
				Type:           C.RuleTypeDefault,
				DefaultOptions: headlessRule,
			},
		},
	}
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", outputPath, err)
	}
	defer f.Close()
	if err := srs.Write(f, plainRuleSet, C.RuleSetVersionCurrent); err != nil {
		return fmt.Errorf("write srs %s: %w", outputPath, err)
	}
	return nil
}

func main() {
	ruleSetDir := "rule-set"

	if err := os.MkdirAll(filepath.Join(ruleSetDir, "geosite"), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir geosite:", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Join(ruleSetDir, "geoip"), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir geoip:", err)
		os.Exit(1)
	}

	for _, src := range upstreamSources {
		fmt.Fprintln(os.Stderr, "fetching", src.key, "from", src.url)
		data, err := fetch(src.url)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}

		outputPath := filepath.Join(ruleSetDir, src.output)
		fmt.Fprintln(os.Stderr, "generating", outputPath)

		switch src.typ {
		case "adguard":
			domains := parseAdGuard(data)
			fmt.Fprintf(os.Stderr, "  domains: %d\n", len(domains))
			if err := writeSRS(outputPath, option.DefaultHeadlessRule{DomainSuffix: domains}); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
		case "clash":
			ipCIDRs := parseClash(data)
			fmt.Fprintf(os.Stderr, "  ip-cidrs: %d\n", len(ipCIDRs))
			if err := writeSRS(outputPath, option.DefaultHeadlessRule{IPCIDR: ipCIDRs}); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
		}
	}

	fmt.Fprintln(os.Stderr, "loading custom rules from custom-rules.json")
	domains, err := loadCustomRules("custom-rules.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	customOutput := filepath.Join(ruleSetDir, "geosite", "geosite-custom.srs")
	fmt.Fprintf(os.Stderr, "generating %s\n  domains: %d\n", customOutput, len(domains))
	if err := writeSRS(customOutput, option.DefaultHeadlessRule{DomainSuffix: domains}); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
