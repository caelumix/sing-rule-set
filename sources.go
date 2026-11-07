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

// AdGuard rule or plain-domain lists, parsed by parseAdGuard
var textSources = []struct {
	url    string
	target string
}{
	// ads, tracking (HaGeZi Normal)
	{"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt", "block"},
	// scam, malware, phishing (TIF medium)
	{"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt", "block"},
	// porn
	{"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nsfw.txt", "block"},
}

var geositeSources = []struct {
	url    string
	target string
}{
	// not in nsfw
	{"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-18comic.srs", "block"},
	// in nsfw, kept on purpose
	{"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-ehentai.srs", "proxy"},
}
