package caldav

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav/caldav"
	"github.com/mathewcsims/protoxide/protonmail"
	"github.com/mathewcsims/protoxide/utils"
)

type backend struct {
	c           *protonmail.Client
	privateKeys openpgp.EntityList
	keyCache    map[string]openpgp.EntityList
	locker      sync.Mutex

	caches   map[string]*calendarCache
	pollers  map[string]bool
	cachesMu sync.Mutex
}

func (b *backend) receiveEvents(events <-chan *protonmail.Event) {
	// Drain and log the core event loop. It is mail-focused (Messages/Contacts)
	// and does not currently surface calendar changes in a parsed form; logging
	// it lets us confirm whether Proton signals calendar deltas here, which is
	// the groundwork for a true push-based refresh. Draining also prevents the
	// events receiver from blocking on send (which the previous no-op did).
	for ev := range events {
		if ev == nil {
			continue
		}
		log.Printf("event loop: id=%s refresh=%d messages=%d contacts=%d notices=%d",
			ev.ID, ev.Refresh, len(ev.Messages), len(ev.Contacts), len(ev.Notices))
	}
}

func (b *backend) CreateCalendar(ctx context.Context, calendar *caldav.Calendar) error {
	// TODO: CreateCalendar
	return errors.ErrUnsupported
}

func readEventCard(event *ical.Event, eventCard protonmail.CalendarEventCard, userKr openpgp.KeyRing, calKr openpgp.KeyRing, keyPacket string) (ical.Props, error) {
	md, err := eventCard.Read(userKr, calKr, keyPacket)
	if err != nil {
		return nil, fmt.Errorf("caldav/readEventCard: error reading event card: (%w)", err)
	}

	data, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("caldav/readEventCard: error reading unverified body: (%w)", err)
	}

	decoded, err := ical.NewDecoder(bytes.NewReader(data)).Decode()
	if err != nil {
		return nil, fmt.Errorf("caldav/readEventCard: error decoding ical data: (%w)", err)
	}

	// The signature can be checked only if md.UnverifiedBody is consumed until
	// EOF
	// TODO: mdc hash mismatch (?)
	/*_, err = io.Copy(io.Discard, md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("caldav/readEventCard: error copying unverified body: (%w)", err)
	}*/

	if err := md.SignatureError; err != nil {
		// Old or imported events are often signed with a key that no longer
		// verifies. For a personal read bridge, decryptability matters more than
		// signature verification — serve the event rather than dropping it.
		log.Printf("caldav/readEventCard: serving event with unverified signature: %v", err)
	}

	children := decoded.Events()
	if len(children) != 1 {
		return nil, fmt.Errorf("caldav/readEventCard: expected VCALENDAR to have exactly one VEVENT")
	}
	decodedEvent := &children[0]

	for _, props := range decodedEvent.Props {
		for _, p := range props {
			event.Props.Set(&p)
		}
	}

	return decoded.Props, nil
}

func toIcalCalendar(event *protonmail.CalendarEvent, userKr openpgp.KeyRing, calKr openpgp.KeyRing) (*ical.Calendar, error) {
	merged := ical.NewEvent()
	calProps := ical.Props{}
	// TODO: handle AttendeesEvents and PersonalEvents
	for _, card := range event.SharedEvents {
		if propsMap, err := readEventCard(merged, card, userKr, calKr, event.SharedKeyPacket); err != nil {
			return nil, fmt.Errorf("caldav/toIcalCalendar: error reading shared event card: (%w)", err)
		} else {
			for name := range propsMap {
				calProps.Set(propsMap.Get(name))
			}
		}
	}

	for _, card := range event.CalendarEvents {
		if propsMap, err := readEventCard(merged, card, userKr, calKr, event.CalendarKeyPacket); err != nil {
			return nil, fmt.Errorf("caldav/toIcalCalendar: error reading calendar event card: (%w)", err)
		} else {
			for name := range propsMap {
				calProps.Set(propsMap.Get(name))
			}
		}
	}

	for _, notification := range event.Notifications {
		alarm := ical.NewComponent(ical.CompAlarm)

		trigger := ical.NewProp("TRIGGER")
		trigger.SetValueType(ical.ValueDuration)
		trigger.Value = notification.Trigger

		alarm.Props.SetText("ACTION", notification.Type.ToIcalAction())
		alarm.Props.Add(trigger)

		merged.Children = append(merged.Children, alarm)
	}

	cal := ical.NewCalendar()

	utils.MapCopy(cal.Props, calProps)
	cal.Children = append(cal.Children, merged.Component)

	return cal, nil
}

func getCalendarObject(b *backend, calId string, calKr openpgp.KeyRing, event *protonmail.CalendarEvent, settings protonmail.CalendarSettings) (*caldav.CalendarObject, error) {
	userKr, exists := b.keyCache[event.Author]
	if event.Author == "" {
		// Events authored by the account owner can come back with no Author set;
		// verify them with the account's own keys rather than fetching public keys
		// for an empty address (which the API rejects with "The Email is required").
		userKr, exists = b.privateKeys, true
	}
	if !exists {
		userKeys, err := b.c.GetPublicKeys(event.Author)
		if err != nil {
			return nil, fmt.Errorf("caldav/getCalendarObject: could not get public keys for author %s: (%w)", event.Author, err)
		}

		for _, userKey := range userKeys.Keys {
			userKeyEntity, err := userKey.Entity()
			if err != nil {
				return nil, fmt.Errorf("caldav/getCalendarObject: error converting user key entity: (%w)", err)
			}

			userKr = append(userKr, userKeyEntity)
		}

		b.locker.Lock()
		b.keyCache[event.Author] = userKr
		b.locker.Unlock()
	}

	if event.Notifications == nil {
		if event.FullDay == 0 {
			event.Notifications = settings.DefaultPartDayNotifications
		} else {
			event.Notifications = settings.DefaultFullDayNotifications
		}
	}

	data, err := toIcalCalendar(event, userKr, calKr)
	if err != nil {
		return nil, fmt.Errorf("caldav/getCalendarObject: error converting to iCal calendar: (%w)", err)
	}

	homeSetPath, err := b.CalendarHomeSetPath(nil)
	if err != nil {
		return nil, fmt.Errorf("caldav/getCalendarObject: error getting calendar home set path: (%w)", err)
	}

	co := &caldav.CalendarObject{
		Path:    homeSetPath + calId + formatCalendarObjectPath(objectToken(data, event.ID)),
		ModTime: time.Unix(int64(event.LastEditTime), 0),
		ETag:    fmt.Sprintf("%X%s", event.LastEditTime, event.ID),
		Data:    data,
	}
	return co, nil
}

func formatCalendarObjectPath(id string) string {
	return "/" + id + ".ics"
}

// objectToken derives the stable CalDAV path token for an event from its
// decrypted data. Proton assigns its own opaque event IDs and *reassigns* them
// when a client-created event is written (the client's chosen path no longer
// resolves), so we key CalDAV resources by the iCalendar UID instead, which is
// stable across the round-trip and across cache reloads. Recurrence overrides,
// which Proton stores as separate events sharing a UID, are disambiguated by
// their RECURRENCE-ID so each remains a distinct resource. Falls back to the
// Proton event ID when no UID is present.
func objectToken(data *ical.Calendar, fallback string) string {
	if data == nil {
		return fallback
	}
	events := data.Events()
	if len(events) == 0 {
		return fallback
	}
	uidProp := events[0].Props.Get(ical.PropUID)
	if uidProp == nil || uidProp.Value == "" {
		return fallback
	}
	uid := uidProp.Value
	if rid := events[0].Props.Get(ical.PropRecurrenceID); rid != nil && rid.Value != "" {
		return uid + "-" + rid.Value
	}
	return uid
}

func (b *backend) CalendarHomeSetPath(ctx context.Context) (string, error) {
	userPrincipal, err := b.CurrentUserPrincipal(ctx)
	if err != nil {
		return "", fmt.Errorf("caldav/CalendarHomeSetPath: could not get current user principal: (%w)", err)
	}
	return userPrincipal + "calendars/", nil
}

func (b *backend) ListCalendars(ctx context.Context) ([]caldav.Calendar, error) {
	protonCals, err := b.c.ListCalendars()
	if err != nil {
		return nil, fmt.Errorf("caldav/ListCalendars: error listing ProtonMail calendars: (%w)", err)
	}

	cals := make([]caldav.Calendar, len(protonCals))
	homeSetPath, err := b.CalendarHomeSetPath(ctx)
	if err != nil {
		return nil, fmt.Errorf("caldav/ListCalendars: error getting calendar home set path: (%w)", err)
	}

	for i, cal := range protonCals {
		calView, err := protonmail.FindMemberViewFromKeyring(cal.Members, b.privateKeys)
		if err != nil {
			return nil, fmt.Errorf("caldav/ListCalendars: error finding member view for calendar %s: (%w)", cal.ID, err)
		}

		caldavCal := caldav.Calendar{
			Path:        homeSetPath + cal.ID,
			Name:        calView.Name,
			Description: calView.Description,
		}
		cals[i] = caldavCal
	}
	return cals, nil
}

func (b *backend) GetCalendar(ctx context.Context, path string) (*caldav.Calendar, error) {
	protonCals, err := b.c.ListCalendars()
	if err != nil {
		return nil, fmt.Errorf("caldav/GetCalendar: error listing ProtonMail calendars: (%w)", err)
	}

	homeSetPath, err := b.CalendarHomeSetPath(ctx)
	if err != nil {
		return nil, fmt.Errorf("caldav/GetCalendar: error getting calendar home set path: (%w)", err)
	}

	id, _ := strings.CutSuffix(path, "/")
	id, _ = strings.CutPrefix(id, homeSetPath)
	for _, cal := range protonCals {
		if cal.ID != id {
			continue
		}

		calView, err := protonmail.FindMemberViewFromKeyring(cal.Members, b.privateKeys)
		if err != nil {
			return nil, fmt.Errorf("caldav/GetCalendar: error finding member view for calendar %s: (%w)", cal.ID, err)
		}

		caldavCal := caldav.Calendar{
			Path:        homeSetPath + cal.ID,
			Name:        calView.Name,
			Description: calView.Description,
		}

		return &caldavCal, nil
	}
	return nil, errors.New("could not find calendar with path")
}

func (b *backend) GetCalendarObject(ctx context.Context, path string, req *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	homeSetPath, err := b.CalendarHomeSetPath(ctx)
	if err != nil {
		return nil, fmt.Errorf("caldav/GetCalendarObject: error getting calendar home set path: (%w)", err)
	}

	calEvtId, _ := strings.CutSuffix(path, "/")
	calEvtId, _ = strings.CutSuffix(calEvtId, ".ics")
	calEvtId, _ = strings.CutPrefix(calEvtId, homeSetPath)
	splitIds := strings.Split(calEvtId, "/")
	if len(splitIds) < 2 {
		return nil, fmt.Errorf("caldav/GetCalendarObject: bad path %s", path)
	}

	calId, token := splitIds[0], splitIds[1]

	// Serve from the decrypted cache when possible. The path token is the event's
	// iCalendar UID (objectToken); resolve it against the cache.
	if o, _, ok := b.findByToken(calId, token); ok {
		return &o, nil
	}

	// Cache miss: fall back to fetching by ID in case the token happens to be a
	// Proton event ID rather than a UID.
	evtId := token
	event, err := b.c.GetCalendarEvent(calId, evtId)
	if err != nil {
		return nil, fmt.Errorf("caldav/GetCalendarObject: error getting calendar event (calId: %s, evtId: %s): (%w)", calId, evtId, err)
	}

	bootstrap, err := b.c.BootstrapCalendar(calId)
	if err != nil {
		return nil, fmt.Errorf("caldav/GetCalendarObject: error bootstrapping calendar (calId: %s): (%w)", calId, err)
	}

	calKr, err := bootstrap.DecryptKeyring(b.privateKeys)
	if err != nil {
		return nil, fmt.Errorf("caldav/GetCalendarObject: error decrypting keyring: (%w)", err)
	}

	co, err := getCalendarObject(b, calId, calKr, event, bootstrap.CalendarSettings)
	if err != nil {
		return nil, fmt.Errorf("caldav/GetCalendarObject: error creating calendar object: (%w)", err)
	}

	return co, nil
}

func (b *backend) ListCalendarObjects(ctx context.Context, path string, req *caldav.CalendarCompRequest) ([]caldav.CalendarObject, error) {
	homeSetPath, err := b.CalendarHomeSetPath(ctx)
	if err != nil {
		return nil, fmt.Errorf("caldav/ListCalendarObjects: error getting calendar home set path: (%w)", err)
	}

	calId, _ := strings.CutSuffix(path, "/")
	calId, _ = strings.CutPrefix(calId, homeSetPath)

	return b.cachedObjects(calId), nil
}

func (b *backend) QueryCalendarObjects(ctx context.Context, path string, query *caldav.CalendarQuery) ([]caldav.CalendarObject, error) {
	homeSetPath, err := b.CalendarHomeSetPath(ctx)
	if err != nil {
		return nil, fmt.Errorf("caldav/QueryCalendarObjects: error getting calendar home set path: (%w)", err)
	}

	calId, _ := strings.CutSuffix(path, "/")
	calId, _ = strings.CutPrefix(calId, homeSetPath)

	if query.CompFilter.Name != ical.CompCalendar {
		return nil, fmt.Errorf("caldav/QueryCalendarObjects: expected top-level comp to be VCALENDAR")
	}
	if len(query.CompFilter.Comps) != 1 || query.CompFilter.Comps[0].Name != ical.CompEvent {
		return nil, fmt.Errorf("caldav/QueryCalendarObjects: expected exactly one nested VEVENT comp")
	}
	cf := &query.CompFilter.Comps[0]

	all := b.cachedObjects(calId)

	// Proton ignores server-side time filtering, so we filter the cache here.
	if cf.Start.IsZero() && cf.End.IsZero() {
		return all, nil
	}
	out := make([]caldav.CalendarObject, 0, len(all))
	for _, o := range all {
		if objectInRange(o, cf.Start, cf.End) {
			out = append(out, o)
		}
	}
	return out, nil
}

func (b *backend) PutCalendarObject(ctx context.Context, path string, calendar *ical.Calendar, opts *caldav.PutCalendarObjectOptions) (loc *caldav.CalendarObject, err error) {
	//TODO: maybe impl opts?
	//TODO: attendees maybe
	homeSetPath, err := b.CalendarHomeSetPath(nil)
	if err != nil {
		return nil, fmt.Errorf("caldav/PutCalendarObject: error getting calendar home set path: (%w)", err)
	}

	calEvtId, _ := strings.CutSuffix(path, "/")
	calEvtId, _ = strings.CutSuffix(calEvtId, ".ics")
	calEvtId, _ = strings.CutPrefix(calEvtId, homeSetPath)
	splitIds := strings.Split(calEvtId, "/")
	if len(splitIds) < 2 {
		return nil, fmt.Errorf("caldav/PutCalendarObject: bad path %s", path)
	}

	calId, token := splitIds[0], splitIds[1]

	events := calendar.Events()
	if len(events) != 1 {
		return nil, fmt.Errorf("caldav/PutCalendarObject: expected PUT VCALENDAR to have exactly one VEVENT")
	}
	event := events[0]

	// The path token is the client's chosen UID. Resolve it to an existing Proton
	// event ID: if found this is an update (pass the Proton ID so UpdateCalendarEvent
	// edits in place); otherwise it's a create (pass the token, which Proton reports
	// as an unknown ID → create). Passing the UID on an update would be seen as an
	// unknown ID and would create a duplicate, so the resolution is essential.
	evtArg := token
	isUpdate := false
	if _, protonID, ok := b.findByToken(calId, token); ok {
		evtArg = protonID
		isUpdate = true
	}

	log.Printf("caldav/PutCalendarObject: writing event (calId=%s, token=%s, update=%v)", calId, token, isUpdate)
	newEvent, err := b.c.UpdateCalendarEvent(calId, evtArg, event, b.privateKeys)
	if err != nil {
		log.Printf("caldav/PutCalendarObject: write FAILED (token=%s): %v", token, err)
		return nil, fmt.Errorf("caldav/PutCalendarObject: error updating calendar event (calId: %s, token: %s): (%w)", calId, token, err)
	}
	log.Printf("caldav/PutCalendarObject: write OK, proton event id=%s", newEvent.ID)

	// Serve the object at the stable UID-derived path the client used, so it is
	// recognised on the next sync and survives a full cache reload (which re-keys
	// the in-memory cache by Proton ID but recomputes the same UID path).
	path = homeSetPath + calId + formatCalendarObjectPath(objectToken(calendar, newEvent.ID))

	obj := caldav.CalendarObject{
		Path:    path,
		ModTime: newEvent.ModifyTime.Time(),
		ETag:    fmt.Sprintf("%X%s", newEvent.LastEditTime, newEvent.ID),
		Data:    calendar,
	}
	// Keep the cache consistent with the write so the new/updated event is
	// visible immediately without waiting for a background refresh.
	b.cacheStore(calId, newEvent.ID, obj)
	return &obj, nil
}

func (b *backend) DeleteCalendarObject(ctx context.Context, path string) error {
	homeSetPath, err := b.CalendarHomeSetPath(nil)
	if err != nil {
		return fmt.Errorf("caldav/DeleteCalendarObject: error getting calendar home set path: (%w)", err)
	}

	calEvtId, _ := strings.CutSuffix(path, "/")
	calEvtId, _ = strings.CutSuffix(calEvtId, ".ics")
	calEvtId, _ = strings.CutPrefix(calEvtId, homeSetPath)
	splitIds := strings.Split(calEvtId, "/")
	if len(splitIds) < 2 {
		return fmt.Errorf("caldav/DeleteCalendarObject: bad path %s", path)
	}

	calId, token := splitIds[0], splitIds[1]

	// Resolve the UID path token to the Proton event ID the delete API needs.
	// Fall back to treating the token itself as the ID (legacy / uncached).
	evtId := token
	if _, protonID, ok := b.findByToken(calId, token); ok {
		evtId = protonID
	}

	if err := b.c.DeleteCalendarEvent(calId, evtId); err != nil {
		return fmt.Errorf("caldav/DeleteCalendarObject: error deleting calendar event (calId: %s, evtId: %s): (%w)", calId, evtId, err)
	}

	b.cacheDelete(calId, evtId)
	return nil
}

func (b *backend) CurrentUserPrincipal(ctx context.Context) (string, error) {
	return "/caldav/", nil
}

func NewHandler(c *protonmail.Client, privateKeys openpgp.EntityList, username string, events <-chan *protonmail.Event) http.Handler {
	if len(privateKeys) == 0 {
		panic("protoxide/caldav: no private key available")
	}

	keyCache := map[string]openpgp.EntityList{username: privateKeys}
	b := &backend{
		c:           c,
		privateKeys: privateKeys,
		keyCache:    keyCache,
		caches:      make(map[string]*calendarCache),
		pollers:     make(map[string]bool),
	}

	if events != nil {
		go b.receiveEvents(events)
	}

	return &caldav.Handler{Backend: b}
}
