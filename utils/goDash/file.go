package goDash

import (
	"fmt"
	"io/ioutil"
)

func FileRead(path string) string {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("read file err:", err.Error())
	}

	// 打印文件内容
	return string(data)
}