package goDash

import (
	"fmt"
	"regexp"
)

func RegMatch(regex string, str string) bool {
	reg, err := regexp.Compile(regex)
	if err != nil {
		fmt.Println(err)
	}

	return reg.MatchString(str)
}