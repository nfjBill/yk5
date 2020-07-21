package goDash

func StrIsEmpty(str string) bool {
	return len(str) == 0
}


func factorial2(num int) int {
	if num == 0 {
		return 1
	}
	return num * factorial2(num-1)
}

func StrSplitLen(str string, length int) []string {
	var strSlice []string
	tmp := str
	i := 0

	var loop func(int)
	loop = func(i int) {
		if len(tmp) > length {
			sl := tmp[0:length]
			strSlice = append(strSlice, sl)
			tmp = tmp[length : len(tmp)]
			loop(i+1)
		} else {
			strSlice = append(strSlice, tmp)
		}
	}

	loop(i)

	return strSlice
}
