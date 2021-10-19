package util

import (
	"encoding/json"
	"os"
	"time"
)

func ConvertSecondsToTime(t int64) time.Time {
	return time.Unix(0, t*int64(time.Second))
}

func GetJsonAsString(i interface{}) (s string) {
	byte, _ := json.MarshalIndent(i, "", "  ")
	s = string(byte)
	return
}

func SaveZipFile(path string, dataByte []byte) error {

	file, err := os.OpenFile(path+".zip", os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)

	if err != nil {
		return err
	}

	defer file.Close()

	_, err = file.Write(dataByte)

	if err != nil {
		return err
	}

	return nil
}
