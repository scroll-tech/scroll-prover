package main

import (
	"io/ioutil"
	"log"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	ServerHost string `yaml:"host,omitempty"`
	ServerURL  string `yaml:"url,omitempty"`
}

type Config struct {
	StartBatch       uint64        `yaml:"start,omitempty"`
	ChunkURLTemplate string        `yaml:"chunkURL"`
	NotifierURL      string        `yaml:"notifierURL"`
	Server           *ServerConfig `yaml:"server,omitempty"`
}

func NewConfig() *Config {
	return &Config{
		Server: &ServerConfig{
			ServerHost: "localhost:8560",
			ServerURL:  "/api",
		},
	}
}

func (cfg *Config) LoadEnv(path string) error {
	return nil
}

func (cfg *Config) Load(path string) error {

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(data, cfg)
	if err != nil {
		return err
	}

	cfgYAML, err := yaml.Marshal(cfg)
	if err != nil {
		log.Fatal("re-marshal config file fail", err)
	} else {
		log.Printf("load config:\n%s", cfgYAML)
	}
	return nil

}
