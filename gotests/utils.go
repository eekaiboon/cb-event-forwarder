package tests

import "encoding/json"

func MarshalJSON(msgs []map[string]interface{}) (string, error) {
	var ret string

	for _, msg := range msgs {
		//msg["cb_server"] = "cbserver"
		marshaled, err := json.Marshal(msg)
		if err != nil {
			return "", err
		}
		ret += string(marshaled) + "\n"
	}

	return ret, nil
}
