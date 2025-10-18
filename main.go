package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
)

var (
	domainPattern = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$`)
	validFilters  = map[string]struct{}{
		"a":     {},
		"www":   {},
		"mail":  {},
		"ns":    {},
		"mx":    {},
		"txt":   {},
		"dkim":  {},
		"dmarc": {},
	}
	defaultOrder = []string{"a", "www", "mail", "ns", "mx", "txt", "dkim", "dmarc"}
)

const dnsQueryTimeout = 5 * time.Second

func sanitizeDomain(input string) string {
	trimmed := strings.TrimSpace(input)
	return strings.TrimSuffix(trimmed, ".")
}

func normalizeDomainInput(current, candidate string) (string, error) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return current, nil
	}
	if idx := strings.LastIndex(candidate, "@"); idx != -1 {
		candidate = candidate[idx+1:]
	}
	candidate = sanitizeDomain(candidate)
	if candidate == "" {
		return current, fmt.Errorf("Harus menyertakan domain yang valid")
	}
	if current != "" {
		return current, fmt.Errorf("Domain tidak valid: hanya boleh satu domain. Jika ada lebih dari satu argumen, yang berawalan '@' dianggap DNS server.")
	}
	return candidate, nil
}

func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	return domainPattern.MatchString(domain)
}

func normalizeResolverAddress(addr string) (string, error) {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return "", fmt.Errorf("DNS server tidak valid: kosong")
	}

	if _, _, err := net.SplitHostPort(trimmed); err == nil {
		return trimmed, nil
	}

	if strings.HasPrefix(trimmed, "[") {
		if !strings.Contains(trimmed, "]") {
			return "", fmt.Errorf("DNS server tidak valid: %q", addr)
		}
		if strings.Contains(trimmed, "]:") {
			if _, _, err := net.SplitHostPort(trimmed); err != nil {
				return "", err
			}
			return trimmed, nil
		}
		return trimmed + ":53", nil
	}

	if ip := net.ParseIP(trimmed); ip != nil {
		return net.JoinHostPort(trimmed, "53"), nil
	}

	if !strings.Contains(trimmed, ":") {
		return net.JoinHostPort(trimmed, "53"), nil
	}

	return "", fmt.Errorf("DNS server tidak valid: %q", addr)
}

func parseArgs(args []string) (string, string, []string, error) {
	var domain string
	var dnsServer string
	var filters []string
	filtersProvided := false

	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "@") {
			if dnsServer != "" {
				return "", "", nil, fmt.Errorf("DNS server duplikat: %q", a)
			}
			dnsServer = strings.TrimSpace(strings.TrimPrefix(a, "@"))
			continue
		}

		if strings.HasPrefix(a, "[") || strings.HasPrefix(a, "--") || strings.HasPrefix(a, "filters=") || strings.HasPrefix(a, "filter=") {
			if filtersProvided {
				return "", "", nil, fmt.Errorf("Filter duplikat: %q", a)
			}
			var raw string
			switch {
			case strings.HasPrefix(a, "--filters="):
				raw = a[len("--filters="):]
			case strings.HasPrefix(a, "--filter="):
				raw = a[len("--filter="):]
			case strings.HasPrefix(a, "filters="):
				raw = a[len("filters="):]
			case strings.HasPrefix(a, "filter="):
				raw = a[len("filter="):]
			case a == "--filters" || a == "--filter":
				i++
				if i >= len(args) {
					return "", "", nil, fmt.Errorf("Argumen filter kosong setelah %q", a)
				}
				raw = args[i]
			case strings.HasPrefix(a, "--"):
				raw = strings.TrimPrefix(a, "--")
			default:
				raw = a
			}

			parsed, err := parseFilterList(raw)
			if err != nil {
				return "", "", nil, err
			}
			filters = parsed
			filtersProvided = true
			continue
		}

		domainCandidate, err := normalizeDomainInput(domain, a)
		if err != nil {
			return "", "", nil, err
		}
		domain = domainCandidate
	}

	if domain == "" {
		return "", "", nil, fmt.Errorf("Harus menyertakan domain yang valid")
	}
	if !isValidDomain(domain) {
		return "", "", nil, fmt.Errorf("Argumen domain tidak valid: %q", domain)
	}
	return domain, dnsServer, filters, nil
}

func parseFilterList(input string) ([]string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return []string{}, nil
	}
	if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
		trimmed = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	}
	if trimmed == "" {
		return []string{}, nil
	}
	parts := strings.Split(trimmed, ",")
	filters := make([]string, 0, len(parts))
	for _, part := range parts {
		name := strings.ToLower(strings.TrimSpace(part))
		if name == "" {
			continue
		}
		if _, ok := validFilters[name]; !ok {
			return nil, fmt.Errorf("Filter tidak dikenal: %q", name)
		}
		filters = append(filters, name)
	}
	return filters, nil
}

func buildFilterSet(filters []string) map[string]bool {
	if len(filters) == 0 {
		return nil
	}
	set := make(map[string]bool, len(filters))
	for _, f := range filters {
		if f == "" {
			continue
		}
		set[f] = true
	}
	return set
}

func shouldInclude(filterSet map[string]bool, key string) bool {
	if filterSet == nil {
		return true
	}
	return filterSet[key]
}

func collectARecords(ctx context.Context, r *net.Resolver, host string) [][]string {
	ips, err := r.LookupHost(ctx, host)
	if err != nil {
		return nil
	}

	records := make([][]string, 0, len(ips))
	for _, ip := range ips {
		hostnames, err := r.LookupAddr(ctx, ip)
		hostname := "-"
		if err == nil && len(hostnames) > 0 {
			hostname = strings.TrimSuffix(hostnames[0], ".")
		}
		records = append(records, []string{ip, hostname})
	}

	return records
}

func formatIPHostLines(records [][]string, hostFirst bool) []string {
	if len(records) == 0 {
		return nil
	}
	lines := make([]string, 0, len(records))
	for _, rec := range records {
		if len(rec) == 0 {
			continue
		}
		ip := rec[0]
		host := ""
		if len(rec) > 1 {
			host = strings.TrimSpace(rec[1])
		}
		if host == "" || host == "-" {
			lines = append(lines, colorizeIP(ip))
			continue
		}
		if hostFirst {
			lines = append(lines, fmt.Sprintf("%s (%s)", host, colorizeIP(ip)))
		} else {
			lines = append(lines, fmt.Sprintf("%s (%s)", colorizeIP(ip), host))
		}
	}
	return lines
}

func formatTXTLines(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	lines := make([]string, 0, len(values))
	for _, val := range values {
		lines = append(lines, strings.TrimSpace(val))
	}
	return lines
}

func printLines(title string, lines []string) {
	color.New(color.FgGreen, color.Bold).Printf("\n[+] %s\n", title)
	if len(lines) == 0 {
		fmt.Println("-")
		return
	}
	for _, line := range lines {
		fmt.Println(line)
	}
}

func firstValueOrDash(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return []string{strings.TrimSpace(values[0])}
}

func colorizeIP(ip string) string {
	if net.ParseIP(ip) == nil {
		return ip
	}
	return color.New(color.FgHiYellow).Sprint(ip)
}

func indentLines(lines []string, prefix string) []string {
	if len(lines) == 0 || prefix == "" {
		return lines
	}
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		out = append(out, prefix+line)
	}
	return out
}

func osintDomain(domain string, resolver string, filters []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), dnsQueryTimeout)
	defer cancel()
	var r *net.Resolver
	if resolver != "" {
		normalized, err := normalizeResolverAddress(resolver)
		if err != nil {
			return err
		}
		dialer := &net.Dialer{Timeout: dnsQueryTimeout}
		r = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, normalized)
			},
		}
	} else {
		r = net.DefaultResolver
	}

	filterSet := buildFilterSet(filters)
	order := filters
	if len(order) == 0 {
		order = defaultOrder
	}

	for _, key := range order {
		switch key {
		case "a":
			if !shouldInclude(filterSet, "a") {
				continue
			}
			apexRecords := collectARecords(ctx, r, domain)
			printLines("A Record", indentLines(formatIPHostLines(apexRecords, false), "    "))
		case "www":
			if !shouldInclude(filterSet, "www") {
				continue
			}
			if wwwRecords := collectARecords(ctx, r, "www."+domain); len(wwwRecords) > 0 {
				printLines("WWW A Record", indentLines(formatIPHostLines(wwwRecords, false), "    "))
			}
		case "mail":
			if !shouldInclude(filterSet, "mail") {
				continue
			}
			if mailRecords := collectARecords(ctx, r, "mail."+domain); len(mailRecords) > 0 {
				printLines("Mail A Record", indentLines(formatIPHostLines(mailRecords, false), "    "))
			}
		case "ns":
			if !shouldInclude(filterSet, "ns") {
				continue
			}
			ns, _ := r.LookupNS(ctx, domain)
			var nsLines []string
			for _, n := range ns {
				ips, _ := r.LookupHost(ctx, n.Host)
				if len(ips) > 0 {
					nsLines = append(nsLines, fmt.Sprintf("%s (%s)", n.Host, colorizeIP(ips[0])))
				} else {
					nsLines = append(nsLines, n.Host)
				}
			}
			printLines("Name Server", indentLines(nsLines, "    "))
		case "mx":
			if !shouldInclude(filterSet, "mx") {
				continue
			}
			mx, _ := r.LookupMX(ctx, domain)
			var mxLines []string
			for _, m := range mx {
				ips, _ := r.LookupHost(ctx, m.Host)
				if len(ips) > 0 {
					mxLines = append(mxLines, fmt.Sprintf("%s (%s)", strings.TrimSuffix(m.Host, "."), colorizeIP(ips[0])))
				} else {
					mxLines = append(mxLines, strings.TrimSuffix(m.Host, "."))
				}
			}
			printLines("MX Record", indentLines(mxLines, "    "))
		case "txt":
			if !shouldInclude(filterSet, "txt") {
				continue
			}
			txt, _ := r.LookupTXT(ctx, domain)
			printLines("TXT / SPF", indentLines(formatTXTLines(txt), "    "))
		case "dkim":
			if !shouldInclude(filterSet, "dkim") {
				continue
			}
			dkimDomain := "default._domainkey." + domain
			dkim, _ := r.LookupTXT(ctx, dkimDomain)
			printLines(fmt.Sprintf("DKIM (%s)", dkimDomain), indentLines(firstValueOrDash(dkim), "    "))
		case "dmarc":
			if !shouldInclude(filterSet, "dmarc") {
				continue
			}
			dmarcDomain := "_dmarc." + domain
			dmarc, _ := r.LookupTXT(ctx, dmarcDomain)
			printLines(fmt.Sprintf("DMARC (%s)", dmarcDomain), indentLines(firstValueOrDash(dmarc), "    "))
		}
	}

	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: osint <domain> [@<dns-server>] [<filters>]")
		fmt.Fprintln(os.Stderr, "Contoh: osint example.com | osint example.com @8.8.8.8 | osint example.com --a,ns,mx")
		os.Exit(1)
	}

	domain, dnsServer, filters, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if dnsServer == "" {
		fmt.Printf("Domain    : %s\n", domain)
		fmt.Printf("DNS Server: (local)\n")
	} else {
		fmt.Printf("Domain    : %s\n", domain)
		fmt.Printf("DNS Server: %s\n", dnsServer)
	}

	if err := osintDomain(domain, dnsServer, filters); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
