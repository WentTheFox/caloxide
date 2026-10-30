package caldav

import (
	"fmt"
	"hash/fnv"
	"sort"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav/caldav"
)

// RFC 4791 section 4.1 wants every component with one UID in a single calendar object
// resource: a recurring series and its edited occurrences belong together. Proton keeps each
// edited occurrence as an event of its own, and the cache holds them that way, one entry per
// Proton event. A client such as Thunderbird keys an item by UID, so serving them as separate
// resources made it re-download the same group of events on every full sync and let recurring
// events blink out of view meanwhile.
//
// The view below is what clients see: one resource per UID. Events that are alone under their
// UID are served exactly as they are cached (same address, same ETag), so nothing changes for
// them. A UID with several events becomes one resource holding the series first and then its
// edited occurrences in order of their RECURRENCE-ID, with an ETag that changes when any of
// them does.

// homeSet is where calendars live, as CalendarHomeSetPath reports it.
const homeSet = "/caldav/calendars/"

// seriesMember is one cached event inside a group.
type seriesMember struct {
	id  string
	rid string // RECURRENCE-ID value, empty for the series itself
	obj caldav.CalendarObject
}

// viewEntry is one resource of the view: the object a client gets and the Proton events
// behind it, series first.
type viewEntry struct {
	obj caldav.CalendarObject
	ids []string
}

// calendarView is the derived, client-facing form of a calendar's cached events.
type calendarView struct {
	gen     uint64
	objects []caldav.CalendarObject
	byToken map[string]viewEntry
}

// viewLocked returns the view for the current contents of the cache, building it again if the
// events changed since it was made. cc.mu must be held.
func (cc *calendarCache) viewLocked(calID string) *calendarView {
	if cc.view == nil || cc.view.gen != cc.gen {
		cc.view = buildView(calID, cc.objects)
		cc.view.gen = cc.gen
	}
	return cc.view
}

// changedLocked records that the cached events changed. Every write to cc.objects calls it.
func (cc *calendarCache) changedLocked() { cc.gen++ }

func eventRID(o caldav.CalendarObject) string {
	if o.Data == nil {
		return ""
	}
	if evs := o.Data.Events(); len(evs) > 0 {
		if p := evs[0].Props.Get(ical.PropRecurrenceID); p != nil {
			return p.Value
		}
	}
	return ""
}

func buildView(calID string, objs map[string]caldav.CalendarObject) *calendarView {
	groups := make(map[string][]seriesMember, len(objs))
	for id, o := range objs {
		token := objectToken(o.Data, id)
		groups[token] = append(groups[token], seriesMember{id: id, rid: eventRID(o), obj: o})
	}

	v := &calendarView{byToken: make(map[string]viewEntry, len(groups))}
	for token, members := range groups {
		sort.Slice(members, func(i, j int) bool {
			a, b := members[i], members[j]
			if (a.rid == "") != (b.rid == "") {
				return a.rid == "" // the series first
			}
			if a.rid != b.rid {
				return a.rid < b.rid
			}
			return a.id < b.id
		})
		e := viewEntry{obj: groupObject(calID, token, members)}
		for _, m := range members {
			e.ids = append(e.ids, m.id)
		}
		v.byToken[token] = e
		v.objects = append(v.objects, e.obj)
	}
	sort.Slice(v.objects, func(i, j int) bool { return v.objects[i].Path < v.objects[j].Path })
	return v
}

// groupObject is the object a client gets for a UID.
func groupObject(calID, token string, members []seriesMember) caldav.CalendarObject {
	path := homeSet + calID + formatCalendarObjectPath(token)
	if len(members) == 1 {
		o := members[0].obj
		o.Path = path
		return o
	}

	first := members[0].obj
	cal := ical.NewCalendar()
	if first.Data != nil {
		for name, vals := range first.Data.Props {
			cal.Props[name] = append([]ical.Prop(nil), vals...)
		}
	}
	h := fnv.New64a()
	var modTime time.Time
	for _, m := range members {
		if m.obj.Data != nil {
			cal.Children = append(cal.Children, m.obj.Data.Children...)
		}
		fmt.Fprintf(h, "%s=%s;", m.id, m.obj.ETag)
		if m.obj.ModTime.After(modTime) {
			modTime = m.obj.ModTime
		}
	}
	return caldav.CalendarObject{
		Path:    path,
		ModTime: modTime,
		ETag:    fmt.Sprintf("G%016X", h.Sum64()),
		Data:    cal,
	}
}
