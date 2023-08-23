package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type Notifier interface {
}

type notifier string

type slackData struct {
	Text  string `json:"text"`
	Agent string `json:"username,omitempty"`
	Icon  string `json:"icon_emoji,omitempty"`
}

func getSlackData(text string, agent string) *slackData {
	return &slackData{
		Text:  text,
		Agent: fmt.Sprintf("Testnet", agent),
		Icon:  "eyes",
	}
}

func notify_slack_channel(url string, slack *slackData) (string, error) {

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

func (n notifier) notify_task_assign(id uint64, agent string) error {
	msg := getSlackData(
		agent,
		fmt.Sprintf("I have receive batch %d", id),
	)
	msg.Icon = "check_mark"
	resp, err := notify_slack_channel(string(n), msg)
	if err == nil {
		log.Println("have send task assigned to slack and remote resp", resp)
	}
	return err
}

func (n notifier) notify_progress(id uint64) error {
	msg := getSlackData(
		"",
		fmt.Sprintf("We have progress to batch %d", id),
	)
	msg.Icon = "party_popper"
	resp, err := notify_slack_channel(string(n), msg)
	if err == nil {
		log.Println("have send progress to slack and remote resp", resp)
	}
	return err
}

func (n notifier) notify_chunk_issue(chunk_id uint64) error {
	msg := getSlackData(
		"",
		fmt.Sprintf("Chunk %d has issued, check it in", chunk_id),
	)
	msg.Icon = "face_screaming_in_fear"
	resp, err := notify_slack_channel(string(n), msg)
	if err == nil {
		log.Println("have send chunk issue to slack and remote resp", resp)
	}
	return err
}

func (n notifier) notify_task_complete(id uint64) error {
	msg := getSlackData(
		"",
		fmt.Sprintf("Batch %d has completed", id),
	)
	msg.Icon = "grinning_face"
	resp, err := notify_slack_channel(string(n), msg)
	if err == nil {
		log.Println("have send task assigned to slack and remote resp", resp)
	}
	return err
}

func (n notifier) notify_task_drop(id uint64) error {
	msg := getSlackData(
		"",
		fmt.Sprintf("Batch %d can not be completed and has been dropped", id),
	)
	msg.Icon = "tired_face"
	resp, err := notify_slack_channel(string(n), msg)
	if err == nil {
		log.Println("have send task assigned to slack and remote resp", resp)
	}
	return err
}
