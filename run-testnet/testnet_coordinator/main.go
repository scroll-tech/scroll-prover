package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

type UpstreamError int

func (sc UpstreamError) Error() string {
	return fmt.Sprintf("Upstream status %d", sc)
}

func readSrcUrl(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, UpstreamError(resp.StatusCode)
	}

	return ioutil.ReadAll(resp.Body)
}

func main() {

	serverConfig := NewConfig()
	if err := serverConfig.Load("config.yaml"); err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	taskAssigner := &TaskAssigner{}

	http.HandleFunc(
		serverConfig.Server.ServerURL+"/chunks",
		chunksHandler(taskAssigner, serverConfig.ChunkURLTemplate),
	)
	http.Handle("/", http.NotFoundHandler())

	log.Printf("Starting server on %s...", serverConfig.Server.ServerHost)
	err := http.ListenAndServe(serverConfig.Server.ServerHost, nil)
	if err != nil {
		log.Print("ListenAndServe: ", err)
	}
}

func chunksHandler(assigner *TaskAssigner, url_template string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		assigned_done := false
		assigned := assigner.assign_new()
		defer func() {
			if !assigned_done {
				assigner.drop(assigned)
			}
		}()
		url := fmt.Sprintf(url_template, assigned)
		resp, err := readSrcUrl(url)
		if statusErr, ok := err.(UpstreamError); ok {
			http.Error(w, statusErr.Error(), int(statusErr))
			return
		} else if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, err = w.Write(resp)
		if err != nil {
			log.Printf("Error writing response: %v\n", err)
			return
		}
		log.Println("send new batch out", assigned)
		assigned_done = true

	}
}
