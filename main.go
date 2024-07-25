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

func scanLog(ctx context.Context, ctl utils.CtLog, domainChan chan<- string, fetchInterval time.Duration) {
    if userSettings.VerboseLogging {
        log.Printf("Starting %s\n", ctl.Client.BaseURI())
    }

    var err error
    blockSize := userSettings.BlockSize

    ctl.Wsth, err = ctl.Client.GetSTH(ctx)
    if err != nil {
        log.Printf("Failed to get initial STH for log %s: %v", ctl.Client.BaseURI(), err)
        return
    }

    if int64(ctl.Wsth.TreeSize) <= blockSize {
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

        nrOfEntries := int64(len(entries.Entries))

        fromNum += nrOfEntries
        toNum = fromNum + 100

        if fromNum >= maxSize {
            break
        }

        // Add delay between fetches
        time.Sleep(fetchInterval)
    }

    if userSettings.VerboseLogging {
        log.Printf("End %s\n", ctl.Client.BaseURI())
    }
}

func main() {
    defer outFile.Close()
    log.SetFlags(log.LstdFlags | log.Lmicroseconds)
    cpuCount := runtime.NumCPU()

    userSettings = utils.UserInput()
    log.Printf("Started cert-sub-go with block size: %d\n", userSettings.BlockSize)
    
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
    go func() {
        defer wgLogs.Done()
        for domain := range domainChan {
            utils.WriteStringToFile(outFile, domain)
        }
    }()

    fetchInterval := time.Duration(userSettings.FetchInterval) * time.Second

    for _, ctl := range ctLogs {
        wg.Add(1)
        sem <- struct{}{}
        go func(ctl utils.CtLog) {
            defer func() {
                <-sem
                wg.Done()
            }()
            scanLog(ctx, ctl, domainChan, fetchInterval)
        }(ctl)
        time.Sleep(time.Second)
    }

    wg.Wait()
    close(domainChan)
    outFile.Close()

    utils.DeduplicateFile(userSettings.OutFilename)
    log.Println("Done Scanning.")
}
