package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/mathewcsims/protoxide/auth"
	"github.com/mathewcsims/protoxide/protonmail"
)

// pushProbe connects to Proton's event-notifier stream and prints everything it
// says, so you can see whether the channel is available to this account and
// whether a change made in Proton produces a ping. It reads nothing else and
// writes nothing to Proton.
func pushProbe(username string, newClient func() *protonmail.Client) {
	bridgePassword, err := askBridgePass()
	if err != nil {
		log.Fatal(err)
	}
	c, _, err := auth.NewManager(newClient).Auth(username, bridgePassword)
	if err != nil {
		log.Fatal(err)
	}

	cals, err := c.ListCalendars()
	if err != nil {
		log.Fatal(err)
	}

	n := c.NewNotifier()
	stamp := func() string { return time.Now().Format("15:04:05") }
	n.OnState = func(up bool, detail string) {
		fmt.Printf("%s  stream %s: %s\n", stamp(), map[bool]string{true: "UP  ", false: "DOWN"}[up], detail)
	}
	n.OnPing = func(p protonmail.NotifierPing) {
		fmt.Printf("%s  PING  type=%s identifier=%s\n", stamp(), p.Type, p.Identifier)
	}

	var loops []protonmail.NotifierLoop
	if u, err := c.GetCurrentUser(); err == nil && u.ID != "" {
		loops = append(loops, protonmail.NotifierLoop{Type: protonmail.NotifierLoopCalendar, Identifier: u.ID})
		fmt.Printf("subscribing: calendar/%s (user)\n", u.ID)
	}
	for _, cal := range cals {
		loops = append(loops, protonmail.NotifierLoop{Type: protonmail.NotifierLoopCalendar, Identifier: cal.ID})
		fmt.Printf("subscribing: calendar/%s\n", cal.ID)
	}
	n.Subscribe(loops...)

	fmt.Println("Waiting for pushes. Create or edit an event in Proton Calendar now; Ctrl-C to stop.")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	n.Run(ctx)
}
