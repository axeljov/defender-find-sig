package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"
	"unicode"
)

const (
	no_malware_detected = 0
	malware_detected    = 2
)
const (
	file_and_dir_custom_scan_type = "3"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Wrong number or arguments. Should be 1")
	}
	fileToScan := os.Args[1]
	fmt.Printf("File to analyze: %s\n", fileToScan)
	f, err := os.Stat(fileToScan)
	if errors.Is(err, os.ErrNotExist) {
		log.Fatal("File does not exist")
	} else if f.IsDir() {
		log.Fatal("File is a directory")
	}

	mpCmdRunPath := getMpCmdRunPath()
	if mpCmdRunPath == "" {
		log.Fatal("Could not find MpCmdRun.exe. Make sure Windows Defender is installed.")
	}
	fmt.Printf("Found MpCmdRun.exe path: %s\n", mpCmdRunPath)

	scanResult := scanFile(fileToScan, mpCmdRunPath)
	if scanResult == no_malware_detected {
		log.Fatal("File was not detected as malware")
	} else if scanResult == malware_detected {
		fmt.Printf("File does contain malware. Starting analysis...\n")
		badByteOffset := findBadByteOffset(fileToScan, mpCmdRunPath)
		printOffendingBytes(fileToScan, badByteOffset)
	} else {
		log.Fatalf("Unknown error returned by scan function: %d\n", scanResult)
	}

	//fmt.Printf("HELLO")
	return
}

func findBadByteOffset(fileToScan string, mpCmdRunPath string) int64 {
	tempDir := os.TempDir()
	if tempDir == "" {
		systemDrive := os.Getenv("SYSTEMDRIVE")
		tempDir = systemDrive + "\\temp"
		os.Create(tempDir)
	}

	fileToScanStat, _ := os.Stat(fileToScan)
	fileSize := fileToScanStat.Size()
	f, _ := os.OpenFile(fileToScan, os.O_RDONLY, 0)
	defer f.Close()

	scanFileBuffer := make([]byte, fileSize)
	f.Read(scanFileBuffer)

	maxSize := fileSize
	chunkSize := fileSize

	for {
		newF, _ := os.CreateTemp(tempDir, "scanme-")
		newF.Write(scanFileBuffer[0:maxSize])
		scanResult := scanFile(newF.Name(), mpCmdRunPath)
		fmt.Printf("scanResult for %s: %d\n", newF.Name(), scanResult)
		newF.Close()
		err := os.Remove(newF.Name())
		if err != nil {
			log.Fatalf("failed to delete temp file: %s", err.Error())
		}

		if chunkSize == 1 {
			fmt.Printf("Found it! :D\n")
			fmt.Printf("offset END of offending bytes is: 0x%x\n", maxSize+1)
			break
		}
		chunkSize = chunkSize / 2
		fmt.Printf("chunkSize: %d\n", chunkSize)

		if scanResult == malware_detected {
			maxSize = maxSize - chunkSize

		} else if scanResult == no_malware_detected {
			maxSize = maxSize + chunkSize
			if maxSize > fileSize {
				log.Fatalf("file scanned does not contain malware")
			}
		} else {
			log.Fatalf("Unexpected scanResult: %d", scanResult)
		}
	}

	return maxSize + 1
}

func scanFile(filePath string, mpCmdRunpath string) int {
	mpCmdRunArgs := []string{"-Scan", "-ScanType", file_and_dir_custom_scan_type, "-File", filePath, "-DisableRemediation"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	runScanCmd := exec.CommandContext(ctx, mpCmdRunpath, mpCmdRunArgs...)
	runScanCmd.Run()
	/*
		if err != nil {
			log.Fatalf("error running scan: %s\n", err.Error())
		}*/

	return runScanCmd.ProcessState.ExitCode()
}

func printOffendingBytes(fileToScan string, offendingByteOffset int64) {
	f, _ := os.OpenFile(fileToScan, os.O_RDONLY, 0)
	offendingBytes := make([]byte, 256)
	f.ReadAt(offendingBytes, offendingByteOffset-256)
	fmt.Println("--------------OFFENDING BYTES START------------")
	for i, b := range offendingBytes {
		fmt.Printf("%02x ", b)
		if ((i + 1) % 16) == 0 {
			fmt.Print("- ")
			for _, r := range []rune(string(offendingBytes[i-16+1 : i+1])) {
				if unicode.IsPrint(r) {
					fmt.Printf("%c", r)
				} else {
					fmt.Printf(".")
				}
			}
			fmt.Println()
		}
	}
	fmt.Println("--------------OFFENDING BYTES END--------------")
}

func getMpCmdRunPath() string {
	cmdRunPathFile := "MpCmdRun.exe"
	knownDirs := []string{"C:\\Program Files\\Windows Defender\\"}

	for _, dir := range knownDirs {
		_, err := os.Stat(dir + cmdRunPathFile)
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			log.Fatalf("error: %s\n", err.Error())
		} else {
			return dir + cmdRunPathFile
		}
	}
	return ""
}
