package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

type notifier struct {
	api            string
	coordinator_id int
}

type slackData struct {
	Text  string `json:"text"`
	Agent string `json:"username,omitempty"`
	Icon  string `json:"icon_emoji,omitempty"`
}

func notifySlackChannel(url string, slack *slackData) (string, error) {

	data, err := json.Marshal(slack)
	if err != nil {
		log.Println("marshal slack notify fail", slack.Text, err)
		return "", err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		log.Println("send slack notify fail", slack.Text, err)
		return "", err
	}
	defer resp.Body.Close()

	return resp.Status, nil
}

const COORDINATOR_COMMON = ":white_check_mark:"
const COORDINATOR_GOODJOB = ":tada:"
const COORDINATOR_BADNEWS = ":tired_face:"

var agentDataTemplate = map[string]string{
	COORDINATOR_COMMON:  "Testnet-coordinator %d",
	COORDINATOR_BADNEWS: "Oh no ... (from coordinator %d)",
	COORDINATOR_GOODJOB: "Coordinator %d: Congraduations!",
}

func (n *notifier) coordinatorNotify(txt string, icon string) error {
	if n.api == "" {
		return nil
	}

	if icon == "" {
		icon = COORDINATOR_COMMON
	}
	resp, err := notifySlackChannel(n.api, &slackData{
		Text:  txt,
		Agent: fmt.Sprintf(agentDataTemplate[icon], n.coordinator_id),
		Icon:  icon,
	})
	if err == nil {
		log.Println("have send coordinate notify and remote resp:", resp)
	}
	return err
}

func (n notifier) nodeProxyNotify(node string, txt string) error {
	if n.api == "" {
		return nil
	}

	node_names := strings.Split(node, ":")

	resp, err := notifySlackChannel(n.api, &slackData{
		Text:  txt,
		Agent: fmt.Sprintf("Testnet-%s", node_names[0]),
		Icon:  ":scream:",
	})
	if err == nil {
		log.Println("have send coordinate notify and remote resp:", resp)
	}
	return err
}
