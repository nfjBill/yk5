package goDash

func ErrLog(err error)  {
	if err != nil {
		panic(err)
	}
}
