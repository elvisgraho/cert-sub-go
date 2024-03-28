package utils

import (
	"fmt"
	"log"
	"strings"
	"sync"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
)

var (
	seenDomains map[string]bool = make(map[string]bool)
	mutex       sync.Mutex
)

// Checks if a domain is a subdomain of any root domain in the global map
func isSubdomain(domain string, userSettings *UserSettings) bool {
	if domain == "" {
		return false
	}

	if userSettings.FilterWildCards {
		domain = strings.ReplaceAll(domain, "*.", "")
	}

	// skip root www subdomains
	if strings.HasPrefix(domain, "www.") {
		domain = strings.Replace(domain, "www.", "", 1)
	}

	mutex.Lock()
	defer mutex.Unlock()

	if seenDomains[domain] {
		return false
	}

	parts := strings.Split(domain, ".")
	for i := range parts {
		parentDomain := strings.Join(parts[i:], ".")
		if _, ok := userSettings.RootDomains[parentDomain]; ok {
			if domain != parentDomain {
				// do not include root domains
				seenDomains[domain] = true
				// Write the string to the file
				fmt.Printf("%s\n", domain)
				return true
			}
		}
	}

	return false
}

// Prints out a short bit of info about |cert|, found at |index| in the
// specified log
func logCertInfo(entry *ct.RawLogEntry, userSettings *UserSettings, domainChan chan<- string) {
	parsedEntry, err := entry.ToLogEntry()

	if x509.IsFatal(err) || parsedEntry.X509Cert == nil {
		log.Printf("Process cert at index %d: <unparsed: %v>", entry.Index, err)
	} else {
		commonName := parsedEntry.X509Cert.Subject.CommonName
		if isSubdomain(commonName, userSettings) {
			domainChan <- commonName
		}
		for _, domain := range parsedEntry.X509Cert.DNSNames {
			if isSubdomain(domain, userSettings) {
				domainChan <- domain
			}
		}
	}
}

// Prints out a short bit of info about |precert|, found at |index| in the
// specified log
func logPrecertInfo(entry *ct.RawLogEntry, userSettings *UserSettings, domainChan chan<- string) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.Precert == nil {
		log.Printf("Process precert at index %d: <unparsed: %v>", entry.Index, err)
	} else {
		commonName := parsedEntry.Precert.TBSCertificate.Subject.CommonName
		if isSubdomain(commonName, userSettings) {
			domainChan <- commonName
		}
		for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
			if isSubdomain(domain, userSettings) {
				domainChan <- domain
			}
		}
	}
}

func ProcessEntries(results *ct.GetEntriesResponse, userSettings *UserSettings, domainChan chan<- string) {

	for _, entry := range results.Entries {
		rle, err := ct.RawLogEntryFromLeaf(0, &entry)
		if err != nil {
			log.Printf("Failed to get parse entry %d: %v", 0, err)
		}
		switch entryType := rle.Leaf.TimestampedEntry.EntryType; entryType {
		case ct.X509LogEntryType:
			logCertInfo(rle, userSettings, domainChan)
		case ct.PrecertLogEntryType:
			logPrecertInfo(rle, userSettings, domainChan)
		default:
			log.Println("Unknown entry")
		}
	}
}
