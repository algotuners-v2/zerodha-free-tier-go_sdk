package utils

import (
	"encoding/json"
	"io"
)

func DeserializeJSON(data io.Reader, object interface{}) error {
	decoder := json.NewDecoder(data)
	return decoder.Decode(object)
}

func ParseJSONToStruct(jsonData []byte, targetStruct interface{}) error {
	return json.Unmarshal(jsonData, targetStruct)
}
