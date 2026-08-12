package models


type Sdk struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

type App struct {
	Id          string `json:"id"`
	VersionName string `json:"version_name"`
	VersionCode int    `json:"version_code"`
	Source      string `json:"source,omitempty"`
}

type Device struct {
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	Os           string `json:"os"`
	OsVersion    string `json:"os_version"`
	ApiLevel     int    `json:"api_level"`
	Abi          string `json:"abi"`
	Locale       string `json:"locale"`
	IsEmulator   bool   `json:"is_emulator"`
}

type ReqBody struct {
	Sdk      Sdk      `json:"sdk"`
	App      App      `json:"app"`
	Device   Device   `json:"device"`
	SentTs   int64    `json:"sent_ts"`
	Events   []Event    `json:"events"` // Giữ open như bản dịch
}

type Event struct {
	EventID      string         `json:"event_id"`
	Seq          int            `json:"seq"`
	Name         string         `json:"name"`
	Ts           int64          `json:"ts"`
	SessionID    string         `json:"session_id"`
	Params       EventParams    `json:"params"`
}

type EventParams struct {
	Threat           string `json:"threat"`
	Source           string `json:"source"`
	Killed           bool   `json:"killed"`
}