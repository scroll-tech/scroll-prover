package main

import (
	"encoding/json"
	"fmt"
	"io"
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

	return io.ReadAll(resp.Body)
}

func main() {

	serverConfig := NewConfig()
	if err := serverConfig.Load("config.yaml"); err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	taskAssigner := construct(serverConfig.StartBatch).setMessenger(serverConfig.NotifierURL, serverConfig.GroupID)

	if serverConfig.ProxyOnly {
		log.Println("stop assignment for proxy-only service")
		taskAssigner.stopAssignment(true)
	}

	http.HandleFunc(
		serverConfig.Server.ServerURL+"/chunks",
		chunksHandler(taskAssigner, serverConfig.ChunkURLTemplate),
	)
	http.HandleFunc(
		serverConfig.Server.ServerURL+"/tasks",
		taskHandler(taskAssigner),
	)
	http.HandleFunc(
		serverConfig.Server.ServerURL+"/status",
		statusHandler(taskAssigner),
	)
	http.HandleFunc(
		serverConfig.Server.ServerURL+"/nodewarning",
		nodeProxyHandler(taskAssigner),
	)
	http.Handle("/", http.NotFoundHandler())

	log.Printf("Starting server on %s...\n", serverConfig.Server.ServerHost)
	err := http.ListenAndServe(serverConfig.Server.ServerHost, nil)
	if err != nil {
		log.Println("ListenAndServe: ", err)
	}
}

type apiDataHead struct {
	BatchIndex int64 `json:"batch_index,omitempty"`
	ChunkIndex int64 `json:"chunk_index,omitempty"`
}

func chunksHandler(assigner *TaskAssigner, url_template string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		disable_spec := r.URL.Query().Get("stop")
		if disable_spec != "" {
			switch disable_spec {
			case "yes":
				assigner.stopAssignment(true)
			case "no":
				assigner.stopAssignment(false)
			default:
				http.Error(w, "should be yes or no", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		} else if assigner.isStopped() {
			log.Println("stop assignment")
			http.Error(w, "assignment stopped", http.StatusForbidden)
			return
		}

		assigned_done := false
		assigned := assigner.assign_new()
		defer func(agent string) {
			log.Println("send new batch out", assigned, assigned_done)
			if !assigned_done {
				assigner.drop(assigned)
			} else {
				assigner.coordinatorNotify(fmt.Sprintf("We have assigned a new batch {%d} to agent %s", assigned, agent), "")
			}
		}(r.RemoteAddr)
		url := fmt.Sprintf(url_template, assigned)
		resp, err := readSrcUrl(url)
		if statusErr, ok := err.(UpstreamError); ok {
			http.Error(w, statusErr.Error(), int(statusErr))
			return
		} else if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		testHead := new(apiDataHead)
		if err := json.Unmarshal(resp, testHead); err != nil {
			log.Println("Testing resp head fail, must given up", err)
			http.Error(w, "Resp is invalid", http.StatusInternalServerError)
			return
		}

		_, err = w.Write(resp)
		if err != nil {
			log.Printf("Error writing response: %v\n", err)
			return
		}

		//assignment is not counted if resp contains unexpected index (often -1 for out of range)
		assigned_done = testHead.BatchIndex == int64(assigned) || testHead.ChunkIndex == int64(assigned)

	}
}

func taskHandler(assigner *TaskAssigner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		done_index := r.URL.Query().Get("done")
		drop_index := r.URL.Query().Get("drop")

		if done_index != "" {
			log.Println("receive done notify for batch:", done_index)
			var ind uint64
			if _, err := fmt.Sscanf(done_index, "%d", &ind); err != nil {
				http.Error(w, "invalid done index, need integer", http.StatusBadRequest)
				return
			}
			if prog, now := assigner.complete(ind); prog {
				assigner.coordinatorNotify(fmt.Sprintf("we have progress to batch %d", now), COORDINATOR_GOODJOB)
			}
		} else if drop_index != "" {
			log.Println("receive drop notify for batch:", drop_index)
			var ind uint64
			if _, err := fmt.Sscanf(drop_index, "%d", &ind); err != nil {
				http.Error(w, "invalid drop index, need integer", http.StatusBadRequest)
				return
			}
			assigner.drop(ind)
			assigner.coordinatorNotify(fmt.Sprintf("Batch %d is once dropped", ind), COORDINATOR_BADNEWS)
		} else {
			http.Error(w, "must query with drop or done", http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func nodeProxyHandler(assigner *TaskAssigner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		chunk_issue_index := r.URL.Query().Get("chunk_issue")
		node_panic_reason := r.URL.Query().Get("panic")

		if chunk_issue_index != "" {
			var ind uint64
			if _, err := fmt.Sscanf(chunk_issue_index, "%d", &ind); err != nil {
				http.Error(w, "invalid index, need integer", http.StatusBadRequest)
				return
			}
			assigner.nodeProxyNotify(r.RemoteAddr, fmt.Sprintf("Prover has issue in chunk %d, check it", ind))
		} else if node_panic_reason != "" {
			assigner.nodeProxyNotify(r.RemoteAddr, fmt.Sprintf("Node status bad because <%s>, check it", node_panic_reason))
		} else {
			http.Error(w, "must query with panic or chunk_issue", http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func statusHandler(assigner *TaskAssigner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		status, rng := assigner.status()

		ret := fmt.Sprintf("{%d-%d}, activing: %v", rng[0], rng[1], status)
		if _, err := w.Write([]byte(ret)); err != nil {
			log.Println("unexpected output of status", err)
		}
	}
}
