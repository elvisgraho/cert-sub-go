package main

import (
	"context"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/elvisgraho/cert-sub-go/utils"
)

var (
	outFile      *os.File
	userSettings *utils.UserSettings
	logListUrl   = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
)

func scanLog(ctx context.Context, ctl utils.CtLog, domainChan chan<- string) {
	if userSettings.VerboseLogging {
		log.Printf("Starting %s\n", ctl.Client.BaseURI())
	}

	// defer wg.Done()
	var err error
	blockSize := userSettings.BlockSize

	ctl.Wsth, err = ctl.Client.GetSTH(ctx)
	if err != nil {
		log.Printf("Failed to get initial STH for log %s: %v", ctl.Client.BaseURI(), err)
		return
	}

	if int64(ctl.Wsth.TreeSize) <= blockSize {
		// if the tree size is smaller than our block size
		blockSize = int64(ctl.Wsth.TreeSize)
	}

	maxSize := int64(ctl.Wsth.TreeSize)
	fromNum := int64(ctl.Wsth.TreeSize) - blockSize
	toNum := fromNum + 100

	for {
		entries, err := ctl.Client.GetRawEntries(ctx, fromNum, toNum)
		if err != nil {
			break
		}

		utils.ProcessEntries(entries, userSettings, domainChan)

		// how many entries server actually gave us
		nrOfEntries := int64(len(entries.Entries))

		fromNum += nrOfEntries
		toNum = fromNum + 100

		if fromNum >= maxSize {
			break
		}
	}

	if userSettings.VerboseLogging {
		log.Printf("End %s\n", ctl.Client.BaseURI())
	}
}

func main() {
	defer outFile.Close() // Close the file when the program exits
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	cpuCount := runtime.NumCPU()

	// Parse user input
	userSettings = utils.UserInput()
	log.Printf("Started cert-sub-go with block size: %d\n", userSettings.BlockSize)
	// Open file for writing
	outFile = utils.OpenOutFile(userSettings.OutFilename)

	ctLogs, err := utils.PopulateLogs(logListUrl)
	if err != nil {
		panic(err)
	}

	var wg sync.WaitGroup
	var wgLogs sync.WaitGroup

	domainChan := make(chan string)
	ctx := context.Background()
	sem := make(chan struct{}, cpuCount)

	wgLogs.Add(1)
	// Start a goroutine to receive domains from the channel
	go func() {
		defer wgLogs.Done() // Notify wait group when this goroutine finishes
		for domain := range domainChan {
			// Handle received domain (printing in this example)
			utils.WriteStringToFile(outFile, domain)
		}
	}()

	// spawn go routines for each log provider
	for _, ctl := range ctLogs {
		wg.Add(1)
		sem <- struct{}{}
		go func(ctl utils.CtLog) {
			defer func() {
				<-sem
				wg.Done()
			}()
			scanLog(ctx, ctl, domainChan)
		}(ctl)
		// spread initial requests by 1 second
		time.Sleep(time.Second)
	}

	wg.Wait()
	close(domainChan)
	outFile.Close()

	// remove duplicates from a file
	utils.DeduplicateFile(userSettings.OutFilename)
	log.Println("Done Scanning.")
}
