package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func WriteStringToFile(outFile *os.File, text string) error {
	_, err := fmt.Fprintf(outFile, "%s\n", text)
	if err != nil {
		return err
	}
	return nil
}

func DeduplicateFile(filename string) error {
	// Open the file for reading and writing
	file, err := os.OpenFile(filename, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create a map to store unique lines
	uniqueLines := make(map[string]bool)

	// Create a slice to store deduplicated lines
	var deduplicatedLines []string

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)

	// Iterate over each line, removing duplicates and empty lines
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !uniqueLines[line] {
			// Mark the line as seen
			uniqueLines[line] = true
			// Add the line to the slice of deduplicated lines
			deduplicatedLines = append(deduplicatedLines, line)
		}
	}

	// Check for scanner errors
	if err := scanner.Err(); err != nil {
		return err
	}

	// Truncate the file to 0 bytes
	if err := file.Truncate(0); err != nil {
		return err
	}

	// Seek back to the beginning of the file
	if _, err := file.Seek(0, 0); err != nil {
		return err
	}

	// Write the deduplicated lines back to the file
	writer := bufio.NewWriter(file)
	for _, line := range deduplicatedLines {
		// Write the line to the file if it's not empty
		if line != "" {
			fmt.Fprintln(writer, line)
		}
	}

	// Flush the writer to ensure all buffered data is written to the file
	if err := writer.Flush(); err != nil {
		return err
	}

	return nil
}

func OpenOutFile(filename string) *os.File {
	// Open the file in append mode, create it if it doesn't exist
	outFile, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		os.Exit(1)
	}

	return outFile
}
