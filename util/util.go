package util

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type InputURL struct {
	URL    string
	Domain string
}

func CreateFile(path string) *os.File {
	if path == "-" || path == "" {
		return os.Stdout
	}

	if strings.Contains(path, "/") {
		dirPath := filepath.Dir(path)
		err := os.MkdirAll(dirPath, 0755)
		if err != nil {
			log.Fatal(err)
		}
	}

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		log.Fatal(err)
	}

	return file
}

func SaveResults(result interface{}, outputFile *os.File) {
	data, err := json.Marshal(result)
	if err != nil {
		log.Println("[UTIL.SaveResults] Error storing result: ", result, err.Error())
	}
	data = append(data, byte('\n'))
	n, err := outputFile.Write(data)
	if err != nil || n != len(data) {
		log.Fatal(err.Error())
	}
}
