package firefly

import (
	"encoding/json"
	"log"
	"net/http"
)

func writeError(w http.ResponseWriter, statusCode int, error string, errorDescription string) {
	w.WriteHeader(statusCode)
	w.Header().Set("Content-Type", "application/json")
	resp := make(map[string]string)
	resp["error"] = error
	if errorDescription != "" {
		resp["error_description"] = errorDescription
	}
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Write(jsonResp)
}
