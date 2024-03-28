package utils

import (
	"flag"
	"fmt"
	"os"
)

type UserSettings struct {
	RootDomains     map[string]bool
	BlockSize       int64
	FilterWildCards bool
	OutFilename     string
	VerboseLogging  bool
}

func UserInput() *UserSettings {
	// Define flags
	var userDomainFile string
	var userSettings UserSettings
	defaultBlockSize := int64(1200000)

	flag.StringVar(&userDomainFile, "r", "", "File containing list of root domains")
	flag.Int64Var(&userSettings.BlockSize, "s", defaultBlockSize, "How many SSL entries to scan for each provider. More entries = further back the data.")
	flag.BoolVar(&userSettings.FilterWildCards, "wildCard", false, "Remove all *. from SSL data.")
	flag.StringVar(&userSettings.OutFilename, "o", "cert-sub-go.out", "Output filename, default: cert-sub-go.out")
	flag.BoolVar(&userSettings.VerboseLogging, "v", false, "Verbose logging.")

	// Parse flags
	flag.Parse()

	// Check if mandatory flag is provided
	if userDomainFile == "" {
		PrintUsage()
		os.Exit(1)
	}

	userSettings.RootDomains = ReadRootDomains(userDomainFile)

	return &userSettings
}

func PrintUsage() {
	fmt.Println("cert-sub-go - Search certificate information for more subdomains.")
	fmt.Println("Usage: cert-sub-go -r targets.txt")
	fmt.Println("Flags:")
	fmt.Println("  -r        <filename>       : File that has all target root domains, ex: tesla.com")
	fmt.Println("  -s        <number>         : How many SSL entries to parse for each provider. More entries = further back the data")
	fmt.Println("  -o        <filename>       : Output filename, default: cert-sub-go.out")
	fmt.Println("  -wildCard <boolean>        : Remove all *. from SSL data.")
	fmt.Println("  -v        <boolean>        : Verbose logging.")
	fmt.Println("Example:")
	fmt.Println("  cert-sub-go -r targets.txt")
}
