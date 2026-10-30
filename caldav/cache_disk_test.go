package caldav

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav/caldav"
	"github.com/mathewcsims/protoxide/config"
)

func event(uid string) *ical.Calendar {
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.PropProductID, "-//test//EN")
	ev := ical.NewEvent()
	ev.Props.SetText(ical.PropUID, uid)
	ev.Props.SetDateTime(ical.PropDateTimeStamp, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	ev.Props.SetDateTime(ical.PropDateTimeStart, time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC))
	ev.Props.SetText(ical.PropSummary, "Secret event "+uid)
	cal.Children = append(cal.Children, ev.Component)
	return cal
}

// unencodable is an event the iCalendar encoder refuses: a second DTSTART.
func unencodable(uid string) *ical.Calendar {
	cal := event(uid)
	extra := ical.NewProp(ical.PropDateTimeStart)
	extra.Value = "20260106T100000Z"
	cal.Children[0].Props.Add(extra)
	return cal
}

func cacheWith(objs map[string]*ical.Calendar) *calendarCache {
	cc := fresh()
	cc.loaded, cc.loadedAt = true, time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	for id, d := range objs {
		cc.objects[id] = caldav.CalendarObject{Path: "/caldav/calendars/cal/" + id + ".ics", ETag: "e-" + id, Data: d}
	}
	return cc
}

func fresh() *calendarCache {
	return &calendarCache{objects: map[string]caldav.CalendarObject{}, byToken: map[string]string{}, recent: map[string]recentMutation{}}
}

func encodeText(t *testing.T, cal *ical.Calendar) string {
	t.Helper()
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// writeLegacy writes a cache file in the format of earlier versions: events as text.
func writeLegacy(t *testing.T, calID string, ics map[string]string, count int) string {
	t.Helper()
	pc := persistedCache{LoadedAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC), Objects: map[string]persistedObject{}, Count: count}
	for id, text := range ics {
		pc.Objects[id] = persistedObject{Path: "/caldav/calendars/cal/" + id + ".ics", ETag: "e-" + id, ICS: text}
	}
	raw, _ := json.Marshal(pc)
	path, _ := cacheFilePath(calID)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func home(t *testing.T) { config.SetConfigHome(t.TempDir()) }

func TestACompleteCacheComesBackComplete(t *testing.T) {
	home(t)
	logs := captureCacheLog(t)
	saveCacheToDisk("cal", cacheWith(map[string]*ical.Calendar{"a": event("a"), "b": event("b"), "c": event("c")}))

	path, _ := cacheFilePath("cal")
	raw, _ := os.ReadFile(path)
	if !bytes.Contains(raw, []byte(`"Tree"`)) || bytes.Contains(raw, []byte(`"ICS"`)) {
		t.Fatalf("new files store the structure, not text:\n%.300s", raw)
	}

	cc := fresh()
	if !loadCacheFromDisk("cal", cc) || !cc.loaded || len(cc.objects) != 3 {
		t.Fatalf("loaded=%v objects=%d", cc.loaded, len(cc.objects))
	}
	if !strings.Contains(logs.String(), "restored 3 events from disk") {
		t.Errorf("log:\n%s", logs.String())
	}
}

// The case that started this: events the encoder refuses used to vanish from the cache.
func TestAnEventTheEncoderRefusesNowSurvivesTheRoundTrip(t *testing.T) {
	home(t)
	saveCacheToDisk("cal", cacheWith(map[string]*ical.Calendar{"a": event("a"), "bad": unencodable("bad")}))

	cc := fresh()
	if !loadCacheFromDisk("cal", cc) || !cc.loaded || len(cc.objects) != 2 {
		t.Fatalf("an event that cannot be written as text must still come back: loaded=%v objects=%d", cc.loaded, len(cc.objects))
	}
	got := cc.objects["bad"].Data.Children[0].Props.Values(ical.PropDateTimeStart)
	if len(got) != 2 || got[1].Value != "20260106T100000Z" {
		t.Fatalf("the event came back changed: %+v", got)
	}
}

func TestStructureRoundTripKeepsEverything(t *testing.T) {
	home(t)
	cal := event("x")
	ev := cal.Children[0]
	p := ical.NewProp("ATTENDEE")
	p.Params = ical.Params{"CN": {"Doe, Jane"}, "PARTSTAT": {"ACCEPTED"}}
	p.Value = "mailto:j@example.com"
	ev.Props.Add(p)
	alarm := ical.NewComponent(ical.CompAlarm)
	alarm.Props.SetText("ACTION", "DISPLAY")
	ev.Children = append(ev.Children, alarm)

	saveCacheToDisk("cal", cacheWith(map[string]*ical.Calendar{"x": cal}))
	cc := fresh()
	loadCacheFromDisk("cal", cc)
	back := cc.objects["x"].Data.Children[0]
	a := back.Props.Get("ATTENDEE")
	if a == nil || a.Params.Get("CN") != "Doe, Jane" || a.Value != "mailto:j@example.com" || len(back.Children) != 1 || back.Children[0].Name != ical.CompAlarm {
		t.Fatalf("lost something: %+v", back)
	}
}

func TestCachesFromEarlierVersionsAreStillRead(t *testing.T) {
	home(t)
	writeLegacy(t, "cal", map[string]string{"a": encodeText(t, event("a")), "b": encodeText(t, event("b"))}, 0) // no Count: old file
	cc := fresh()
	if !loadCacheFromDisk("cal", cc) || len(cc.objects) != 2 || !cc.loaded {
		t.Fatalf("loaded=%v objects=%d", cc.loaded, len(cc.objects))
	}
}

func TestUnreadableEventsMakeTheCacheIncompleteNotSilentlySmaller(t *testing.T) {
	home(t)
	logs := captureCacheLog(t)
	writeLegacy(t, "cal", map[string]string{
		"a": encodeText(t, event("a")),
		"b": "BEGIN:VCALENDAR\r\nthis line has no separator at all\r\nEND:VCALENDAR\r\n",
	}, 2)
	cc := fresh()
	if loadCacheFromDisk("cal", cc) || cc.loaded {
		t.Fatal("a cache that lost an event must not come back as complete")
	}
	if len(cc.objects) != 1 {
		t.Fatalf("what could be read should still be kept for early sync, got %d", len(cc.objects))
	}
	if out := logs.String(); !strings.Contains(out, "only 1 of 2 events") || !strings.Contains(out, "loaded again in full") || !strings.Contains(out, "1 unreadable: 1x ") {
		t.Errorf("the restore must explain itself:\n%s", out)
	}
}

func TestACountLargerThanTheFileMeansEventsWereLost(t *testing.T) {
	home(t)
	writeLegacy(t, "cal", map[string]string{"a": encodeText(t, event("a")), "b": encodeText(t, event("b"))}, 3)
	if loadCacheFromDisk("cal", fresh()) {
		t.Fatal("the file says it was given 3 events to save but holds 2")
	}
}

func TestStoredTextIsRepairedLikeEventsFromProton(t *testing.T) {
	home(t)
	text := strings.Replace(encodeText(t, event("a")), "SUMMARY:Secret event a", "SUMMARY:Secret event a\r\nand more words", 1)
	writeLegacy(t, "cal", map[string]string{"a": text}, 1)
	cc := fresh()
	if !loadCacheFromDisk("cal", cc) || len(cc.objects) != 1 {
		t.Fatalf("a repairable event must be restored, got %d (loaded=%v)", len(cc.objects), cc.loaded)
	}
}

func TestTheFirstSaveOverAnOldFileKeepsItOnce(t *testing.T) {
	home(t)
	path := writeLegacy(t, "cal", map[string]string{"a": encodeText(t, event("a"))}, 1)
	old, _ := os.ReadFile(path)

	saveCacheToDisk("cal", cacheWith(map[string]*ical.Calendar{"a": event("a")}))
	bak, err := os.ReadFile(path + ".bak")
	if err != nil || !bytes.Equal(bak, old) {
		t.Fatalf("the old file was not kept: %v", err)
	}
	if now, _ := os.ReadFile(path); bytes.Equal(now, old) || !bytes.Contains(now, []byte(`"Tree"`)) {
		t.Fatal("the cache was not rewritten in the new format")
	}

	saveCacheToDisk("cal", cacheWith(map[string]*ical.Calendar{"a": event("a"), "b": event("b")}))
	if again, _ := os.ReadFile(path + ".bak"); !bytes.Equal(again, old) {
		t.Fatal("the backup of the old file must not be overwritten by later saves")
	}
}

func TestNoBackupIsMadeOfANewFormatFile(t *testing.T) {
	home(t)
	saveCacheToDisk("cal", cacheWith(map[string]*ical.Calendar{"a": event("a")}))
	saveCacheToDisk("cal", cacheWith(map[string]*ical.Calendar{"a": event("a"), "b": event("b")}))
	path, _ := cacheFilePath("cal")
	if _, err := os.Stat(path + ".bak"); err == nil {
		t.Fatal("a file in the new format needs no backup")
	}
}

// --- the dry run ---

func TestCacheCheckReportsAndChangesNothing(t *testing.T) {
	home(t)
	dir := filepath.Dir(mustPath(t, "x"))
	saveCacheToDisk("good", cacheWith(map[string]*ical.Calendar{"a": event("a"), "b": unencodable("b")}))
	writeLegacy(t, "old", map[string]string{"a": encodeText(t, event("a"))}, 1)
	writeLegacy(t, "broken", map[string]string{"a": encodeText(t, event("a")), "b": "garbage without a separator\r\n"}, 2)
	os.WriteFile(filepath.Join(dir, "calcache-junk.json"), []byte("not json"), 0o600)

	before := snapshotDir(t, dir)
	reports, err := CheckCacheDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if after := snapshotDir(t, dir); after != before {
		t.Fatalf("the dry run changed the directory:\nbefore %s\nafter  %s", before, after)
	}

	by := map[string]CacheFileReport{}
	var all strings.Builder
	for _, r := range reports {
		by[r.Calendar] = r
		all.WriteString(r.String())
	}
	if g := by["good"]; !g.Complete() || g.FromTree != 2 || g.Restored != 2 {
		t.Errorf("good = %+v", g)
	}
	if o := by["old"]; !o.Complete() || o.FromText != 1 {
		t.Errorf("old = %+v", o)
	}
	if b := by["broken"]; b.Complete() || b.Restored != 1 || len(b.Failed) != 1 {
		t.Errorf("broken = %+v", b)
	}
	if j := by["junk"]; j.Unusable == "" || j.Complete() {
		t.Errorf("junk = %+v", j)
	}
	out := all.String()
	for _, want := range []string{"complete: 2 of 2", "INCOMPLETE: 1 of 2", "UNUSABLE", "Nothing is written to Proton", "rewritten as structure"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Secret event") || strings.Contains(out, "garbage without") {
		t.Errorf("the report must never contain event text:\n%s", out)
	}
}

func TestCacheCheckOnAnEmptyDirectory(t *testing.T) {
	reports, err := CheckCacheDir(t.TempDir())
	if err != nil || len(reports) != 0 {
		t.Fatalf("%v %v", reports, err)
	}
}

func mustPath(t *testing.T, name string) string {
	p, err := config.Path(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// snapshotDir fingerprints names, sizes and modification times of everything in dir.
func snapshotDir(t *testing.T, dir string) string {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	var sb strings.Builder
	for _, e := range entries {
		fi, _ := e.Info()
		sb.WriteString(e.Name() + "|" + fi.ModTime().String() + "|" + string(rune(fi.Size())) + ";")
	}
	return sb.String()
}

// --- logging ---

func TestUnverifiedSignaturesAreSummarisedNotListed(t *testing.T) {
	logs := captureCacheLog(t)
	for i := 0; i < 156; i++ {
		noteUnverifiedSignature(errors.New("openpgp: invalid signature: RSA verification failure"))
	}
	logUnverifiedSignatures("cal")
	logUnverifiedSignatures("cal") // nothing left to say
	out := logs.String()
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, "156 event(s)") || !strings.Contains(out, "served anyway") {
		t.Fatalf("expected one summary line:\n%s", out)
	}
}

func TestErrorClassGroupsLineNumbersAndStaysShort(t *testing.T) {
	a := errorClass(errors.New("ical: line 12: missing colon"))
	b := errorClass(errors.New("ical: line 4087: missing colon"))
	if a != b {
		t.Errorf("%q != %q", a, b)
	}
	if got := errorClass(errors.New(strings.Repeat("x", 500))); len(got) > 100 {
		t.Errorf("not shortened: %d", len(got))
	}
}

func captureCacheLog(t *testing.T) *bytes.Buffer {
	var buf bytes.Buffer
	logSet(&buf)
	t.Cleanup(func() { logSet(os.Stderr) })
	return &buf
}
