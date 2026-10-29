package caldav

import (
	"bytes"
	"context"
	"encoding/hex"
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
	webdav "github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/caldav"
	"github.com/mathewcsims/protoxide/notify"
	"github.com/mathewcsims/protoxide/protonmail"
	"github.com/mathewcsims/protoxide/utils"
)

// Debug, when true, enables verbose per-request logging (object counts, cache
// misses). It is off by default so a long-running service doesn't produce an
// unbounded log; meaningful events (writes, poller changes, cache loads, errors,
// auth failures) are always logged. Set via the -debug flag in main.
var Debug bool

type backend struct {
	c           *protonmail.Client
	privateKeys openpgp.EntityList
	keyCache    map[string]openpgp.EntityList
	locker      sync.Mutex

	caches   map[string]*calendarCache
	pollers  map[string]bool
	cachesMu sync.Mutex

	push     pushState
	notifier *protonmail.Notifier
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

// sanitizeICS repairs decrypted iCalendar text that the strict decoder rejects.
// The common defect in imported events is an unescaped line break inside a
// property value: the continuation appears as its own physical line with no
// name:value separator, which the decoder reports as "missing colon". Such lines
// (no ':' and no ';', and not a fold continuation) are merged back onto the
// previous logical line; blank lines are dropped. Lines that already look like
// valid content lines pass through untouched.
func sanitizeICS(data []byte) []byte {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			out = append(out, line) // proper fold continuation
			continue
		}
		if !strings.ContainsAny(line, ":;") {
			// Orphaned value continuation: merge into the previous logical line.
			if len(out) > 0 {
				out[len(out)-1] += line
			}
			continue
		}
		out = append(out, line)
	}
	return []byte(strings.Join(out, "\r\n") + "\r\n")
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
		// Imported events sometimes carry content the strict parser rejects — most
		// often an unescaped newline in a value, whose second physical line has no
		// name:value separator ("missing colon"). Repair and retry rather than
		// dropping the whole event.
		repaired, rerr := ical.NewDecoder(bytes.NewReader(sanitizeICS(data))).Decode()
		if rerr != nil {
			return nil, fmt.Errorf("caldav/readEventCard: error decoding ical data: (%w)", err)
		}
		log.Printf("caldav/readEventCard: recovered a malformed event via sanitize")
		decoded = repaired
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
		return safeSegment(fallback)
	}
	events := data.Events()
	if len(events) == 0 {
		return safeSegment(fallback)
	}
	uidProp := events[0].Props.Get(ical.PropUID)
	if uidProp == nil || uidProp.Value == "" {
		return safeSegment(fallback)
	}
	token := safeSegment(uidProp.Value)
	if rid := events[0].Props.Get(ical.PropRecurrenceID); rid != nil && rid.Value != "" {
		token += "~" + safeSegment(rid.Value)
	}
	return token
}

// safeSegment returns s if it is usable verbatim as a single URL path segment and
// XML text, otherwise a hex-encoded, namespaced form that always is. UIDs from
// clients use the safe set (so a client-created event round-trips to the same
// href), but UIDs from imported/Proton-side events can contain '/', ':', '|',
// quotes or spaces, which break the href in the multistatus and the path parsing.
// Encoding need not be reversible: the token is matched by recomputation
// (findByToken), so both sides derive the same value from the same event.
func safeSegment(s string) string {
	if isURLSafe(s) {
		return s
	}
	return "enc." + hex.EncodeToString([]byte(s))
}

func isURLSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_' || r == '~' || r == '@' || r == '=':
		default:
			return false
		}
	}
	return true
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
			CTag:        b.cacheCTag(cal.ID),
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
			CTag:        b.cacheCTag(cal.ID),
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
	if Debug {
		log.Printf("caldav/GetCalendarObject: cache MISS token=%s, falling back to Proton fetch", token)
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

	objs, ready := b.cachedObjects(calId)
	if !ready {
		// Cold load in progress: don't serve an empty list (the client would treat
		// the calendar as emptied). Signal a transient error so it retries.
		log.Printf("caldav/ListCalendarObjects: calendar still loading, asking client to retry")
		return nil, webdav.NewHTTPError(http.StatusServiceUnavailable, fmt.Errorf("caldav: calendar still loading"))
	}
	if Debug {
		log.Printf("caldav/ListCalendarObjects: returning %d objects", len(objs))
	}
	return objs, nil
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

	all, ready := b.cachedObjects(calId)
	if !ready {
		log.Printf("caldav/QueryCalendarObjects: calendar still loading, asking client to retry")
		return nil, webdav.NewHTTPError(http.StatusServiceUnavailable, fmt.Errorf("caldav: calendar still loading"))
	}

	// Proton ignores server-side time filtering, so we filter the cache here.
	if cf.Start.IsZero() && cf.End.IsZero() {
		if Debug {
			log.Printf("caldav/QueryCalendarObjects: no time filter, returning all %d objects", len(all))
		}
		return all, nil
	}
	out := make([]caldav.CalendarObject, 0, len(all))
	for _, o := range all {
		if objectInRange(o, cf.Start, cf.End) {
			out = append(out, o)
		}
	}
	if Debug {
		log.Printf("caldav/QueryCalendarObjects: time filter [%s .. %s], returning %d of %d objects",
			cf.Start.Format(time.RFC3339), cf.End.Format(time.RFC3339), len(out), len(all))
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

	// UpdateCalendarEvent mutates the event it is given while building Proton's
	// encrypted cards (it strips UID and other properties). The event shares its
	// underlying component with our `calendar`, so writing directly would corrupt
	// the copy we cache and the UID/path we derive for the response — leaving the
	// object served at a Proton-ID path that no longer matches the client's PUT
	// URL, so the client can't recognise its own event until a full resync.
	// Hand the write an isolated clone and keep `calendar` pristine.
	writeCal := cloneCalendar(calendar)
	writeEvent := writeCal.Events()[0]

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
	newEvent, err := b.c.UpdateCalendarEvent(calId, evtArg, writeEvent, b.privateKeys)
	if err != nil {
		log.Printf("caldav/PutCalendarObject: write FAILED (token=%s): %v", token, err)
		notify.Send("failure", "caldav-write", "protoxide: calendar write failed",
			fmt.Sprintf("Writing an event to Proton failed: %v", err))
		return nil, fmt.Errorf("caldav/PutCalendarObject: error updating calendar event (calId: %s, token: %s): (%w)", calId, token, err)
	}
	log.Printf("caldav/PutCalendarObject: write OK, proton event id=%s", newEvent.ID)

	// Serve the object at the stable UID-derived path the client used (from the
	// pristine calendar), so the client recognises its own event immediately and
	// the object survives a full cache reload (which recomputes the same path).
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

// cloneCalendar returns a deep copy of a calendar by round-tripping it through
// the encoder, so mutations to the copy (e.g. by Proton's write path) don't
// affect the original. Falls back to the original if the round-trip fails.
func cloneCalendar(cal *ical.Calendar) *ical.Calendar {
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		return cal
	}
	clone, err := ical.NewDecoder(&buf).Decode()
	if err != nil {
		return cal
	}
	return clone
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
	b.startPush()

	return &caldav.Handler{Backend: b}
}
