package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type File struct {
	path   string
	finder *Finder

	pti *PcapTagsInfo

	baseName          string // 文件名, 包含后缀
	name              string // 文件名, 不包含后缀
	ext               string // 后缀
	relativeDirectory string // 相对于 finder.Directory 的路径信息, 不包含文件名
	relativePath      string // 相对于 finder.Directory 的路径信息, 包含文件名
	info              os.FileInfo
}

func (f *File) parse() {
	f.baseName = filepath.Base(f.path)
	f.ext = filepath.Ext(f.baseName)
	f.name = f.baseName[:len(f.baseName)-len(f.ext)]
	if strings.HasPrefix(f.path, f.finder.absDirectory) {
		f.relativePath = f.path[len(f.finder.absDirectory)+1:]
	} else { // should be startswith f.finder.workingDirectory
		f.relativePath = f.path[len(f.finder.workingDirectory)+1:]
	}
	f.relativeDirectory = filepath.Dir(f.relativePath)
}

func (f *File) isValidPcapSuffix() error {
	if f.baseName[0] == '.' {
		return errors.New("hidden file")
	}

	if f.ext == "" {
		return errors.New("no suffix")
	}

	if f.ext != ".pcap" && f.ext != ".pcapng" && f.ext != ".cap" {
		return errors.New("invalid suffix")
	}
	return nil
}

func (f *File) copyTo(dst string) error {
	return copyTo(f.path, dst)
}

func (f *File) delete() {
	if config.KeepData {
		return
	}
	_ = os.Remove(f.path)
}
