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
	if RUNNING || errorHappened {
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

func expandTags(tagsSets ...[]string) [][]string {
	lens := func(i int) int {return len(tagsSets[i])}

	var tags [][]string

	ix := make([]int, len(tagsSets))

	for ; ix[0] < lens(0); {
		var r []string
		for j, k := range ix {
			r = append(r, tagsSets[j][k])
		}

		tags = append(tags, r)

		for j := len(ix) - 1; j >= 0; j -- {
			ix[j] ++
			if j == 0 || ix[j] < lens(j) {
				break
			}
			ix[j] = 0
		}
	}
	return tags
}

func exists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if !os.IsNotExist(err) {
		return true
	}
	return false
}

func allInOthers(setsA []string, setsB[]string) bool {
	for _, ia := range setsA {
		in := false
		for _, ib := range setsB {
			if ia == ib {
				in = true
				break
			}
		}
		if !in {
			return false
		}
	}
	return true
}