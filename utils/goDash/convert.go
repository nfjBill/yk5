package goDash

import (
	"log"
	"strconv"
)

func Str2Int(str string) int {
	re, err := strconv.Atoi(str)
	if err != nil {
		log.Fatalf("utils convert str2int, fail to parse '%v': %v", str, err)
	}
	return re
}

func Int2Str(i int) string {
	return strconv.Itoa(i)
}

//func Str2TimeDuration(str string) int {
//	re, err := strconv.(str)
//	if err != nil {
//		log.Fatalf("utils convert str2int, fail to parse '%v': %v", str, err)
//	}
//	return re
//}