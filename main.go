package main

// TODO Add more sources from below
// https://github.com/AdguardTeam/AdGuardSDNSFilter/tree/master/Filters
// https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
// https://www.stopforumspam.com/downloads/toxic_domains_whole.txt
// https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-unbound.conf
import (
	"io/ioutil"
	"github.com/golang/glog"
	"github.com/asaskevich/govalidator"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/samber/lo"
	"github.com/spf13/pflag"
	"os"
	"strings"
	"regexp"
)

var ipRegex, _ = regexp.Compile("^[0127]{1,3}\\.0\\.0\\.[01]\\s+(.*)$")
var outpath string
var ignoredDomains []string

func parseLine(line string) string {
	x := ipRegex.FindStringSubmatch(line)
	if len(x) > 0 {
		return x[1]
	}
	return line
}

func main() {
	defer glog.Flush()
	
	pflag.StringVar(&outpath, "output", "/etc/unbound/local.d/blocklist.conf", "Path to output file")
	pflag.StringSliceVar(&ignoredDomains, "ignored-domains", []string{"localhost"}, "domains to ignore")
	pflag.Parse()

	startingURL := "https://v.firebog.net/hosts/lists.php?type=tick"
	ch := make(chan string)

	go fetch(startingURL, ch)
	urls := lo.Filter(strings.Split(<-ch, "\n"), func(value string, _ int) bool {
		return govalidator.IsURL(value)
	})

	if len(urls) == 0 {
		glog.Error("Could not fetch from " + startingURL)
		os.Exit(1)
	}

	for _, url := range urls {
		go fetch(url, ch)
	}

	// TODO Can I use a waitgroup here instead and then just use the inner for loop?
	uniqueDomains := map[string]bool{}
	for range urls {
		for _, line := range strings.Split(<-ch, "\n") {
			// strip comments
			commentIndex := strings.Index(line, "#")
			if commentIndex >= 0 {
				line = line[0:commentIndex]
			}
			line = strings.ToLower(strings.TrimSpace(line))

			if len(line) == 0 {
				continue
			}

			x := parseLine(line)
			uniqueDomains[x] = true
		}
	}

	for _, ignored := range ignoredDomains {
		delete(uniqueDomains, ignored)
	}

	if len(uniqueDomains) < 100_000 {
		glog.Fatal("Total number of domains is less than 100,000. Likely an error with retriving or parsing has occurred")
		os.Exit(1)
	}

	f, err := os.Create(outpath)
	if err != nil {
        panic(err)
    }
	defer f.Close()

	for domain := range uniqueDomains {
		if govalidator.IsDNSName(domain) || govalidator.IsIP(domain) {
			f.WriteString("local-zone: " + domain + " always_nxdomain\n")
		} else {
			glog.Warningf("could not parse %q", domain)
		}
	}
	f.Sync()
}

func fetch(url string, ch chan<- string){
	resp, err := retryablehttp.Get(url)
	if err != nil {
		glog.Error(err)
		ch <- ""
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		glog.Error(err)
		ch <- ""
		return
	}

	ch <- string(body)
}
