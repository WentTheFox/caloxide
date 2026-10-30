package caldav

import (
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"bytes"

	"github.com/emersion/go-ical"
	"github.com/mathewcsims/protoxide/protonmail"
)

// An event is assembled from several of Proton's cards, and the iCalendar encoder (which
// the CalDAV server runs every time it hands an event to a client) is strict: exactly one
// UID and DTSTAMP, at most one of many other properties, not DTEND together with DURATION,
// no raw line break inside a value. An event that fails it is listed to the client but its
// data cannot be sent (the server reports a 500 for that property), so it never shows up.
// makeEncodable repairs the ways an event can fail, using only what the encoder says is
// wrong. It changes the copy this server holds and serves; nothing is written to Proton.

// productID is what a calendar without a PRODID is given.
const productID = "-//caloxide//Proton Calendar//EN"

// eventFacts are what Proton's event record knows, for properties the cards left out.
type eventFacts struct {
	uid   string
	stamp time.Time
}

var (
	reWantProp  = regexp.MustCompile(`failed to encode "([A-Z]+)": want (exactly|at most) one "([A-Za-z0-9-]+)" property, got (\d+)`)
	reCRLF      = regexp.MustCompile(`property value: contains a CR or LF`)
	reQuote     = regexp.MustCompile(`param value: contains a double-quote`)
	reEndAndDur = regexp.MustCompile(`only one of DTEND and DURATION can be specified`)
)

func encodes(cal *ical.Calendar) error {
	var buf bytes.Buffer
	return ical.NewEncoder(&buf).Encode(cal)
}

// makeEncodable repairs cal until it encodes, at most maxRepairs times. It returns a short
// label for each repair made (no event content), and the encoder's error if something is
// wrong that it does not know how to fix.
func makeEncodable(cal *ical.Calendar, facts eventFacts) (repairs []string, err error) {
	const maxRepairs = 16
	for i := 0; i < maxRepairs; i++ {
		err = encodes(cal)
		if err == nil {
			return repairs, nil
		}
		label, ok := repairOnce(cal, facts, err.Error())
		if !ok {
			return repairs, err
		}
		repairs = append(repairs, label)
	}
	return repairs, fmt.Errorf("still not encodable after %d repairs: %w", maxRepairs, err)
}

func repairOnce(cal *ical.Calendar, facts eventFacts, msg string) (label string, ok bool) {
	if m := reWantProp.FindStringSubmatch(msg); m != nil {
		comp, name, got := m[1], m[3], m[4]
		if got == "0" {
			return addMissing(cal, comp, name, facts)
		}
		// More than one of a property that may appear once: keep the first.
		n := 0
		for _, c := range findComponents(cal.Component, comp) {
			if vals := c.Props[name]; len(vals) > 1 {
				c.Props[name] = vals[:1]
				n++
			}
		}
		if n > 0 {
			return fmt.Sprintf("kept the first of several %s in %s", name, comp), true
		}
		return "", false
	}
	switch {
	case reEndAndDur.MatchString(msg):
		for _, c := range findComponents(cal.Component, ical.CompEvent) {
			delete(c.Props, ical.PropDuration)
		}
		return "dropped DURATION where DTEND is present", true
	case reCRLF.MatchString(msg):
		fixed := false
		walk(cal.Component, func(c *ical.Component) {
			for name, vals := range c.Props {
				for i := range vals {
					if strings.ContainsAny(vals[i].Value, "\r\n") {
						vals[i].Value = escapeBreaks(vals[i].Value)
						fixed = true
					}
				}
				c.Props[name] = vals
			}
		})
		return "escaped line breaks inside property values", fixed
	case reQuote.MatchString(msg):
		fixed := false
		walk(cal.Component, func(c *ical.Component) {
			for _, vals := range c.Props {
				for i := range vals {
					for pname, pvals := range vals[i].Params {
						for j := range pvals {
							if strings.Contains(pvals[j], `"`) {
								pvals[j] = strings.ReplaceAll(pvals[j], `"`, "")
								fixed = true
							}
						}
						vals[i].Params[pname] = pvals
					}
				}
			}
		})
		return "removed double quotes inside parameter values", fixed
	}
	return "", false
}

// addMissing supplies a property the encoder requires and the cards did not carry.
func addMissing(cal *ical.Calendar, comp, name string, facts eventFacts) (string, bool) {
	var value string
	switch {
	case comp == "VCALENDAR" && name == ical.PropVersion:
		value = "2.0"
	case comp == "VCALENDAR" && name == ical.PropProductID:
		value = productID
	case comp == ical.CompEvent && name == ical.PropDateTimeStamp:
		t := facts.stamp
		if t.IsZero() {
			t = time.Now()
		}
		value = t.UTC().Format("20060102T150405Z")
	case comp == ical.CompEvent && name == ical.PropUID && facts.uid != "":
		value = facts.uid
	default:
		return "", false
	}
	targets := []*ical.Component{cal.Component}
	if comp != "VCALENDAR" {
		targets = findComponents(cal.Component, comp)
	}
	for _, c := range targets {
		if c.Props == nil {
			c.Props = ical.Props{}
		}
		c.Props.Set(&ical.Prop{Name: name, Value: value})
	}
	return fmt.Sprintf("added the missing %s to %s", name, comp), len(targets) > 0
}

func escapeBreaks(s string) string {
	s = strings.ReplaceAll(s, "\r\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\n`)
	return strings.ReplaceAll(s, "\n", `\n`)
}

func walk(c *ical.Component, f func(*ical.Component)) {
	f(c)
	for _, child := range c.Children {
		walk(child, f)
	}
}

func findComponents(root *ical.Component, name string) []*ical.Component {
	var out []*ical.Component
	walk(root, func(c *ical.Component) {
		if c.Name == name {
			out = append(out, c)
		}
	})
	return out
}

// mergeProps copies the properties of one card into the event, keeping every value of a
// property that appears more than once (EXDATE, ATTENDEE, ...). A property already set by
// an earlier card is replaced as a whole, so cards that repeat UID or DTSTAMP do not
// produce duplicates. (The copy used to go value by value with Set, which left only the
// last value of each property.)
func mergeProps(dst, src ical.Props) {
	for name, vals := range src {
		dst[name] = append([]ical.Prop(nil), vals...)
	}
}

// What repairs were made, counted so a load logs one summary instead of a line per event.
var serving struct {
	mu         sync.Mutex
	repaired   map[string]int // label -> events
	events     int            // events that needed at least one repair
	unservable map[string]int // error class -> events still not encodable
	oddities   map[string]int // things in Proton's event record that the event data does not show
}

// noteOddity counts an event whose data disagrees with Proton's own record of it.
func noteOddity(label string) {
	serving.mu.Lock()
	defer serving.mu.Unlock()
	if serving.oddities == nil {
		serving.oddities = map[string]int{}
	}
	serving.oddities[label]++
}

func noteServing(repairs []string, err error) {
	serving.mu.Lock()
	defer serving.mu.Unlock()
	if len(repairs) > 0 {
		if serving.repaired == nil {
			serving.repaired = map[string]int{}
		}
		serving.events++
		seen := map[string]bool{}
		for _, r := range repairs {
			if !seen[r] {
				seen[r] = true
				serving.repaired[r]++
			}
		}
	}
	if err != nil {
		if serving.unservable == nil {
			serving.unservable = map[string]int{}
		}
		serving.unservable[errorClass(err)]++
	}
}

// logServing writes the summary of repairs and of events that still cannot be served.
func logServing(calID string) {
	serving.mu.Lock()
	repaired, events, unservable, oddities := serving.repaired, serving.events, serving.unservable, serving.oddities
	serving.repaired, serving.events, serving.unservable, serving.oddities = nil, 0, nil, nil
	serving.mu.Unlock()

	if len(oddities) > 0 {
		log.Printf("cache %s: events read since the last summary whose data does not show what Proton's own record of the event says: %s",
			calID, countsSummary(oddities))
	}

	if events > 0 {
		log.Printf("cache %s: %d event(s) read since the last summary needed repair to be served to clients: %s",
			calID, events, countsSummary(repaired))
	}
	if len(unservable) > 0 {
		n := 0
		for _, c := range unservable {
			n += c
		}
		log.Printf("cache %s: %d event(s) read since the last summary cannot be served to clients, because they do not encode as iCalendar (%s)",
			calID, n, countsSummary(unservable))
	}
}

func countsSummary(m map[string]int) string {
	type kv struct {
		k string
		n int
	}
	var all []kv
	for k, n := range m {
		all = append(all, kv{k, n})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].k < all[j].k
	})
	var parts []string
	for i, e := range all {
		if i == 4 {
			parts = append(parts, fmt.Sprintf("and %d more kinds", len(all)-4))
			break
		}
		parts = append(parts, fmt.Sprintf("%dx %s", e.n, e.k))
	}
	return strings.Join(parts, "; ")
}

// recordOddities lists the facts in Proton's own record of an event that the assembled event
// data does not show. A single edited occurrence without its RECURRENCE-ID, for instance,
// would be served at the address of its series.
func recordOddities(record *protonmail.CalendarEvent, ev *ical.Component) []string {
	var out []string
	if record.RecurrenceID != nil && ev.Props.Get(ical.PropRecurrenceID) == nil {
		out = append(out, "a recurrence id in the record but no RECURRENCE-ID in the data")
	}
	if len(record.Exdates) > 0 && len(ev.Props.Values(ical.PropExceptionDates)) == 0 {
		out = append(out, "excluded dates in the record but no EXDATE in the data")
	}
	if record.RRule != nil && ev.Props.Get(ical.PropRecurrenceRule) == nil {
		out = append(out, "a recurrence rule in the record but no RRULE in the data")
	}
	return out
}
