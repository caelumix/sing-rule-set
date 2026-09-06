package main

var geoIPSources = []struct {
	url    string
	output string
}{
	{
		url:    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/TelegramNL/TelegramNL.list",
		output: "geoip/geoip-telegram@nl.srs",
	},
	{
		url:    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/TelegramSG/TelegramSG.list",
		output: "geoip/geoip-telegram@sg.srs",
	},
	{
		url:    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/TelegramUS/TelegramUS.list",
		output: "geoip/geoip-telegram@us.srs",
	},
}

const blockHTTPDNSURL = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/AdGuard/BlockHttpDNS/BlockHttpDNS.txt"

var geositeSources = []struct {
	url    string
	target string
}{
	{"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-porn.srs", "block"},
	{"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ai-!cn.srs", "proxy"},
	{"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-google.srs", "proxy"},
	{"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-wikimedia.srs", "proxy"},
	{"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-x.srs", "proxy"},
}
