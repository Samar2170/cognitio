package internal

import "time"

var EventTypes []string = []string{
	"login",
	"signup",
	"logout",
	"userCreated",
}

type Event struct {
	EventType string
	Payload   interface{}
	CreatedAt time.Time
}
