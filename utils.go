package main

import (
	"io"
	"os"
)

func contains(arr []string, t string) bool {
	for _, item := range arr {
		if item == t {
			return true
		}
	}
	return false
}

func exit(code int) {
	cleanup(code)
	os.Exit(code)
}

func terminate() {
	waiting := 0
	if RUNNING {
		waiting = 1
	}
	RUNNING = false
	exit(waiting)
}

func copyTo(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	buf := make([]byte, 1024*2) // 2M buffer size
	for {
		n, err := source.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}
		if _, err := destination.Write(buf[:n]); err != nil {
			return err
		}
	}
	return nil
}

func deleteFile(path string) {
	_ = os.Remove(path)
}
