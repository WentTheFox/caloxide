package caldav

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

var testKey = func() *[32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	return &k
}()

func otherKey() *[32]byte {
	var k [32]byte
	k[0] = 0xff
	return &k
}

func TestACompleteCacheComesBackComplete(t *testing.T) {
	home(t)
	logs := captureCacheLog(t)
	saveCacheToDisk("cal", cacheWith(map[string]*ical.Calendar{"a": event("a"), "b": event("b"), "c": event("c")}), testKey)

	path, _ := cacheFilePath("cal")
	raw, _ := os.ReadFile(path)
	if !bytes.Contains(raw, []byte(sealedFormat)) || bytes.Contains(raw, []byte(`"Tree"`)) || bytes.Contains(raw, []byte("Secret event")) {
		t.Fatalf("the file must be sealed, with nothing readable inside:\n%.300s", raw)
	}

	cc := fresh()
	if !loadCacheFromDisk("cal", cc, testKey) || !cc.loaded || len(cc.objects) != 3 {
		t.Fatalf("loaded=%v objects=%d", cc.loaded, len(cc.objects))
	}
	if !strings.Contains(logs.String(), "restored 3 events from disk") {
		t.Errorf("log:\n%s", logs.String())
	}
}

// The case that started this: events the encoder refuses used to vanish from the cache.
func TestAnEventTheEncoderRefusesNowSurvivesTheRoundTrip(t *testing.T) {
	home(t)
	saveCacheToDisk("cal", cacheWith(map[string]*ical.Calendar{"a": event("a"), "bad": unencodable("bad")}), testKey)

	cc := fresh()
	if !loadCacheFromDisk("cal", cc, testKey) || !cc.loaded || len(cc.objects) != 2 {
		t.Fatalf("an event that cannot be written as text must still come back: loaded=%v objects=%d", cc.loaded, len(cc.objects))
	}
	// What is stored is exactly what was saved: nothing is lost on the way to disk...
	path, _ := cacheFilePath("cal")
	raw, _ := os.ReadFile(path)
	pc, _, err := openCacheFile(raw, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if stored := pc.Objects["bad"].Tree.Children[0].Props.Values(ical.PropDateTimeStart); len(stored) != 2 || stored[1].Value != "20260106T100000Z" {
		t.Fatalf("the stored event is not what was saved: %+v", stored)
	}
	// ... and what is restored is repaired so that it can be served (see makeEncodable).
	got := cc.objects["bad"].Data.Children[0].Props.Values(ical.PropDateTimeStart)
	if len(got) != 1 || got[0].Value != "20260105T100000Z" {
		t.Fatalf("the restored event should keep its first DTSTART: %+v", got)
	}
	if err := encodes(cc.objects["bad"].Data); err != nil {
		t.Fatalf("the restored event still cannot be served: %v", err)
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

	saveCacheToDisk("cal", cacheWith(map[string]*ical.Calendar{"x": cal}), testKey)
	cc := fresh()
	loadCacheFromDisk("cal", cc, testKey)
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
	if !loadCacheFromDisk("cal", cc, testKey) || len(cc.objects) != 2 || !cc.loaded {
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
	if loadCacheFromDisk("cal", cc, testKey) || cc.loaded {
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
	if loadCacheFromDisk("cal", fresh(), testKey) {
		t.Fatal("the file says it was given 3 events to save but holds 2")
	}
}

func TestStoredTextIsRepairedLikeEventsFromProton(t *testing.T) {
	home(t)
	text := strings.Replace(encodeText(t, event("a")), "SUMMARY:Secret event a", "SUMMARY:Secret event a\r\nand more words", 1)
	writeLegacy(t, "cal", map[string]string{"a": text}, 1)
	cc := fresh()
	if !loadCacheFromDisk("cal", cc, testKey) || len(cc.objects) != 1 {
		t.Fatalf("a repairable event must be restored, got %d (loaded=%v)", len(cc.objects), cc.loaded)
	}
}

func TestAnOldPlaintextCacheIsReadOnceAndThenSealed(t *testing.T) {
	home(t)
	logs := captureCacheLog(t)
	path := writeLegacy(t, "cal", map[string]string{"a": encodeText(t, event("a")), "b": encodeText(t, event("b"))}, 2)
	old, _ := os.ReadFile(path)
	if !bytes.Contains(old, []byte("Secret event")) {
		t.Fatal("setup: the old file should be readable plaintext")
	}

	cc := fresh()
	if !loadCacheFromDisk("cal", cc, testKey) || len(cc.objects) != 2 {
		t.Fatal("an unencrypted cache from an earlier version must still be read")
	}
	if !strings.Contains(logs.String(), "did not encrypt it") {
		t.Errorf("say so in the log:\n%s", logs.String())
	}

	cc.loaded = true
	saveCacheToDisk("cal", cc, testKey)
	now, _ := os.ReadFile(path)
	if bytes.Contains(now, []byte("Secret event")) || bytes.Contains(now, []byte("BEGIN:VCALENDAR")) || !bytes.Contains(now, []byte(sealedFormat)) {
		t.Fatalf("the cache must be sealed after the next save:\n%.200s", now)
	}
}

func TestSavingRemovesTheUnencryptedBackupOfVersion061(t *testing.T) {
	home(t)
	logs := captureCacheLog(t)
	path := writeLegacy(t, "cal", map[string]string{"a": encodeText(t, event("a"))}, 1)
	os.WriteFile(path+".bak", []byte("plaintext calendar"), 0o600)

	saveCacheToDisk("cal", cacheWith(map[string]*ical.Calendar{"a": event("a")}), testKey)
	if _, err := os.Stat(path + ".bak"); err == nil {
		t.Fatal("a plaintext copy next to the sealed cache defeats the encryption")
	}
	if !strings.Contains(logs.String(), "removed the unencrypted backup") {
		t.Errorf("log:\n%s", logs.String())
	}
}

// --- encryption ---

func sealedOnDisk(t *testing.T) (string, []byte) {
	t.Helper()
	home(t)
	saveCacheToDisk("cal", cacheWith(map[string]*ical.Calendar{"a": event("a"), "b": unencodable("b")}), testKey)
	path, _ := cacheFilePath("cal")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, raw
}

func TestSealedCacheContainsNothingReadable(t *testing.T) {
	path, raw := sealedOnDisk(t)
	for _, leak := range []string{"Secret event", "VEVENT", "DTSTART", "20260105", "Summary", "SUMMARY", "mailto", "/caldav/calendars", "e-a"} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Errorf("%q is readable in the file", leak)
		}
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Error("the temporary file was left behind")
	}
}

func TestSealedCacheOpensOnlyWithItsKey(t *testing.T) {
	_, _ = sealedOnDisk(t)
	logs := captureCacheLog(t)

	cc := fresh()
	if !loadCacheFromDisk("cal", cc, testKey) || len(cc.objects) != 2 {
		t.Fatal("the right key must open it")
	}

	for name, key := range map[string]*[32]byte{"wrong key": otherKey(), "no key": nil} {
		c := fresh()
		if loadCacheFromDisk("cal", c, key) || c.loaded || len(c.objects) != 0 {
			t.Fatalf("%s: a cache that cannot be opened must give nothing, got loaded=%v objects=%d", name, c.loaded, len(c.objects))
		}
	}
	out := logs.String()
	for _, want := range []string{"cannot be decrypted", "bridge password changed", "no key is available", "loaded from Proton"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
}

func TestATamperedCacheIsRejectedNotServed(t *testing.T) {
	path, raw := sealedOnDisk(t)
	var env sealedFile
	json.Unmarshal(raw, &env)
	box := []byte(env.Sealed)
	box[len(box)/2] ^= 1 // flip one bit of the base64 text, somewhere in the middle
	env.Sealed = string(box)
	tampered, _ := json.Marshal(env)
	os.WriteFile(path, tampered, 0o600)

	if loadCacheFromDisk("cal", fresh(), testKey) {
		t.Fatal("a changed byte must make the cache unusable")
	}
}

func TestEverySaveUsesAFreshNonce(t *testing.T) {
	path, first := sealedOnDisk(t)
	saveCacheToDisk("cal", cacheWith(map[string]*ical.Calendar{"a": event("a"), "b": unencodable("b")}), testKey)
	second, _ := os.ReadFile(path)
	if bytes.Equal(first, second) {
		t.Fatal("saving the same calendar twice gave identical files: the nonce is being reused")
	}
}

func TestWithoutAKeyNothingIsWritten(t *testing.T) {
	home(t)
	noKeyOnce = sync.Once{} // the warning is logged once per process; this test needs to see it
	logs := captureCacheLog(t)
	saveCacheToDisk("cal", cacheWith(map[string]*ical.Calendar{"a": event("a")}), nil)
	path, _ := cacheFilePath("cal")
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a plaintext cache must never be the fallback")
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Fatal("a temporary file was written")
	}
	if !strings.Contains(logs.String(), "no key to encrypt") {
		t.Errorf("say why nothing is saved:\n%s", logs.String())
	}
}

func TestTheHandlerOptionSetsTheKey(t *testing.T) {
	b := &backend{}
	WithCacheKey(testKey)(b)
	if b.cacheKey != testKey {
		t.Fatal("WithCacheKey did not set the key")
	}
}

// --- the dry run ---

func TestCacheCheckReportsAndChangesNothing(t *testing.T) {
	home(t)
	dir := filepath.Dir(mustPath(t, "x"))
	saveCacheToDisk("good", cacheWith(map[string]*ical.Calendar{"a": event("a"), "b": unencodable("b")}), testKey)
	writeLegacy(t, "old", map[string]string{"a": encodeText(t, event("a"))}, 1)
	writeLegacy(t, "broken", map[string]string{"a": encodeText(t, event("a")), "b": "garbage without a separator\r\n"}, 2)
	os.WriteFile(filepath.Join(dir, "calcache-junk.json"), []byte("not json"), 0o600)

	before := snapshotDir(t, dir)
	reports, err := CheckCacheDir(dir, func() (*[32]byte, error) { return testKey, nil })
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
	for _, want := range []string{"complete, encrypted: 2 of 2", "complete, NOT encrypted: 1 of 1", "INCOMPLETE: 1 of 2", "UNUSABLE", "Nothing is written to Proton", "rewritten as structure", "encrypted the next time"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Secret event") || strings.Contains(out, "garbage without") {
		t.Errorf("the report must never contain event text:\n%s", out)
	}
}

func TestCacheCheckOnAnEmptyDirectory(t *testing.T) {
	reports, err := CheckCacheDir(t.TempDir(), nil)
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

func TestCacheCheckOpensSealedCachesWithTheKeyAndAsksOnlyWhenNeeded(t *testing.T) {
	home(t)
	dir := filepath.Dir(mustPath(t, "x"))
	saveCacheToDisk("sealed", cacheWith(map[string]*ical.Calendar{"a": event("a"), "b": event("b")}), testKey)

	asked := 0
	reports, _ := CheckCacheDir(dir, func() (*[32]byte, error) { asked++; return testKey, nil })
	if asked != 1 || len(reports) != 1 || !reports[0].Complete() || !reports[0].Sealed || reports[0].Restored != 2 {
		t.Fatalf("asked=%d reports=%+v", asked, reports)
	}
	if out := reports[0].String(); !strings.Contains(out, "complete, encrypted") || strings.Contains(out, "Secret event") {
		t.Errorf("output:\n%s", out)
	}

	// a directory with no sealed file never asks for the password
	plain := t.TempDir()
	config.SetConfigHome(plain)
	writeLegacy(t, "old", map[string]string{"a": encodeText(t, event("a"))}, 1)
	asked = 0
	rs, _ := CheckCacheDir(filepath.Dir(mustPath(t, "x")), func() (*[32]byte, error) { asked++; return testKey, nil })
	if asked != 0 || !rs[0].Complete() || rs[0].Sealed {
		t.Fatalf("asked=%d %+v", asked, rs)
	}
	if !strings.Contains(rs[0].String(), "NOT encrypted") {
		t.Errorf("an unencrypted cache must be called that:\n%s", rs[0].String())
	}
}

func TestCacheCheckWithAWrongOrMissingKeyChangesNothingAndSaysWhy(t *testing.T) {
	home(t)
	dir := filepath.Dir(mustPath(t, "x"))
	saveCacheToDisk("sealed", cacheWith(map[string]*ical.Calendar{"a": event("a")}), testKey)
	before := snapshotDir(t, dir)

	for name, keyFn := range map[string]func() (*[32]byte, error){
		"wrong key":     func() (*[32]byte, error) { return otherKey(), nil },
		"no way to ask": nil,
		"asking failed": func() (*[32]byte, error) { return nil, errors.New("no terminal") },
	} {
		reports, err := CheckCacheDir(dir, keyFn)
		if err != nil || len(reports) != 1 || reports[0].Complete() || reports[0].Unusable == "" {
			t.Fatalf("%s: %+v %v", name, reports, err)
		}
	}
	if snapshotDir(t, dir) != before {
		t.Fatal("the dry run changed the directory")
	}
}
