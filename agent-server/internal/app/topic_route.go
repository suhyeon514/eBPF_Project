package app

import (
	"strings"

	"github.com/suhyeon514/eBPF_Project/internal/model"
)

const (
	topicTetragonNetwork = "tetragon.network"
	topicTetragonFile    = "tetragon.file"
	topicTetragonProcess = "tetragon.process"
	topicTetragonAuth    = "tetragon.auth"
	topicNetwork         = "network"
	topicJournald        = "journald"
	topicAuditd          = "auditd"
	topicSensor          = "sensor"
)

func routeTopic(ev model.Event) string {
	et := string(ev.EventType)

	if ev.EventType == model.EventSensorHealth || ev.Sensor != nil {
		return topicSensor
	}

	if ev.Collector.Name == "tetragon" {
		switch {
		case strings.HasPrefix(et, "edr.process."):
			return topicTetragonProcess
		case strings.HasPrefix(et, "edr.network."):
			return topicTetragonNetwork
		case strings.HasPrefix(et, "edr.file."):
			return topicTetragonFile
		case strings.HasPrefix(et, "edr.auth."):
			return topicTetragonAuth
		default:
			return topicSensor
		}
	}

	switch ev.Collector.Name {
	case "journald":
		return topicJournald
	case "auditd":
		return topicAuditd
	}

	if ev.Network != nil || strings.HasPrefix(et, "edr.network.") {
		return topicNetwork
	}

	return topicSensor
}
