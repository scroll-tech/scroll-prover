package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type notifier string

type slackData struct {
	Text  string `json:"text"`
	Agent string `json:"username,omitempty"`
	Icon  string `json:"icon_emoji,omitempty"`
}

func getSlackData(text string, agent string) *slackData {
	return &slackData{
		Text:  text,
		Agent: fmt.Sprintf("Testnet-%s", agent),
		Icon:  "eyes",
	}
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

var agentData = map[string]string{
	COORDINATOR_COMMON:  "Testnet-coordinator",
	COORDINATOR_BADNEWS: "Oh no ...",
	COORDINATOR_GOODJOB: "Congraduations!",
}

func (n notifier) coordinatorNotify(txt string, icon string) error {
	if n == "" {
		return nil
	}

	if icon == "" {
		icon = COORDINATOR_COMMON
	}
	resp, err := notifySlackChannel(string(n), &slackData{
		Text:  txt,
		Agent: agentData[icon],
		Icon:  icon,
	})
	if err == nil {
		log.Println("have send coordinate notify and remote resp:", resp)
	}
	return err
}

func (n notifier) nodeProxyNotify(node string, txt string) error {
	if n == "" {
		return nil
	}

	resp, err := notifySlackChannel(string(n), &slackData{
		Text:  txt,
		Agent: fmt.Sprintf("Testnet-%s", node),
		Icon:  ":scream:",
	})
	if err == nil {
		log.Println("have send coordinate notify and remote resp:", resp)
	}
	return err
}
