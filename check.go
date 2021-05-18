package main

import (
	"errors"
	logger "github.com/sirupsen/logrus"
	"regexp"
)

var (
	idPattern, _ = regexp.Compile("(?i)^[a-z][a-z0-9_-]+$")
)

type Checker interface {
	check() (err error)
}

func check(checker Checker) {
	err := checker.check()
	if err != nil {
		logger.Errorf("auto check failed: %s - %s\n", checker, err)
		errorHappened = true
		terminate()
	}
}

func checkId(id string) error {
	if id == "" {
		return errors.New("id can not be null")
	}
	if id == "all" {
		return errors.New("id can not be `all`")
	}
	if !idPattern.MatchString(id) {
		return errors.New("invalid id format")
	}
	return nil
}
