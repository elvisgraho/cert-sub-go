package utils

import (
	"bufio"
	"fmt"
	"log"
	"os"
)

// Reads root domains from a file into the global rootDomains map
func ReadRootDomains(filePath string) map[string]bool {
	// Check if the provided file path exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("File '%s' does not exist\n", filePath)
		os.Exit(1)
	}

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error parsing URL:", err)
		os.Exit(1)
	}
	defer file.Close()

	// Initialize the map
	rootDomains := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		rootDomains[scanner.Text()] = true
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error parsing URL:", err)
		os.Exit(1)
	}

	return rootDomains
}
