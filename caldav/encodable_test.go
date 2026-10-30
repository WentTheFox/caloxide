package caldav

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-ical"
)

var factsFixture = eventFacts{uid: "uid-from-proton", stamp: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)}

func ev(cal *ical.Calendar) *ical.Component { return cal.Children[0] }

func TestAnEventThatAlreadyEncodesIsLeftAlone(t *testing.T) {
	cal := event("a")
	repairs, err := makeEncodable(cal, factsFixture)
	if err != nil || len(repairs) != 0 {
		t.Fatalf("repairs=%v err=%v", repairs, err)
	}
	if got := ev(cal).Props.Get(ical.PropSummary).Value; got != "Secret event a" {
		t.Fatalf("summary changed: %q", got)
	}
}

func TestEachKnownDefectIsRepairedAndNothingElseChanges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(*ical.Calendar)
		repair string
		check  func(t *testing.T, cal *ical.Calendar)
	}{
		{"no VERSION", func(c *ical.Calendar) { delete(c.Props, ical.PropVersion) }, "added the missing VERSION to VCALENDAR",
			func(t *testing.T, c *ical.Calendar) {
				if c.Props.Get(ical.PropVersion).Value != "2.0" {
					t.Error("VERSION should be 2.0")
				}
			}},
		{"no PRODID", func(c *ical.Calendar) { delete(c.Props, ical.PropProductID) }, "added the missing PRODID to VCALENDAR",
			func(t *testing.T, c *ical.Calendar) {
				if c.Props.Get(ical.PropProductID).Value != productID {
					t.Error("PRODID missing")
				}
			}},
		{"no DTSTAMP", func(c *ical.Calendar) { delete(ev(c).Props, ical.PropDateTimeStamp) }, "added the missing DTSTAMP to VEVENT",
			func(t *testing.T, c *ical.Calendar) {
				if got := ev(c).Props.Get(ical.PropDateTimeStamp).Value; got != "20260304T050607Z" {
					t.Errorf("DTSTAMP should come from the event record, got %q", got)
				}
			}},
		{"no UID", func(c *ical.Calendar) { delete(ev(c).Props, ical.PropUID) }, "added the missing UID to VEVENT",
			func(t *testing.T, c *ical.Calendar) {
				if got := ev(c).Props.Get(ical.PropUID).Value; got != "uid-from-proton" {
					t.Errorf("UID should come from the event record, got %q", got)
				}
			}},
		{"two DTSTART", func(c *ical.Calendar) {
			ev(c).Props.Add(&ical.Prop{Name: ical.PropDateTimeStart, Value: "20260106T100000Z"})
		}, "kept the first of several DTSTART in VEVENT",
			func(t *testing.T, c *ical.Calendar) {
				if v := ev(c).Props.Values(ical.PropDateTimeStart); len(v) != 1 || v[0].Value != "20260105T100000Z" {
					t.Errorf("the first DTSTART should win: %+v", v)
				}
			}},
		{"two SUMMARY", func(c *ical.Calendar) {
			ev(c).Props.Add(&ical.Prop{Name: ical.PropSummary, Value: "second"})
		}, "kept the first of several SUMMARY in VEVENT",
			func(t *testing.T, c *ical.Calendar) {
				if v := ev(c).Props.Values(ical.PropSummary); len(v) != 1 || v[0].Value != "Secret event a" {
					t.Errorf("%+v", v)
				}
			}},
		{"DTEND and DURATION", func(c *ical.Calendar) {
			ev(c).Props.Add(&ical.Prop{Name: ical.PropDateTimeEnd, Value: "20260105T110000Z"})
			ev(c).Props.Add(&ical.Prop{Name: ical.PropDuration, Value: "PT1H"})
		}, "dropped DURATION where DTEND is present",
			func(t *testing.T, c *ical.Calendar) {
				if len(ev(c).Props.Values(ical.PropDuration)) != 0 || len(ev(c).Props.Values(ical.PropDateTimeEnd)) != 1 {
					t.Error("DTEND should stay, DURATION go")
				}
			}},
		{"line break in a value", func(c *ical.Calendar) {
			ev(c).Props.Set(&ical.Prop{Name: ical.PropDescription, Value: "line one\nline two\r\nline three"})
		}, "escaped line breaks inside property values",
			func(t *testing.T, c *ical.Calendar) {
				if got := ev(c).Props.Get(ical.PropDescription).Value; got != `line one\nline two\nline three` {
					t.Errorf("got %q", got)
				}
			}},
		{"quote in a parameter", func(c *ical.Calendar) {
			ev(c).Props.Add(&ical.Prop{Name: "ATTENDEE", Value: "mailto:a@x", Params: ical.Params{"CN": {`Jane "JJ" Doe`}}})
		}, "removed double quotes inside parameter values",
			func(t *testing.T, c *ical.Calendar) {
				if got := ev(c).Props.Get("ATTENDEE").Params.Get("CN"); got != "Jane JJ Doe" {
					t.Errorf("got %q", got)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cal := event("a")
			tc.break_(cal)
			if encodes(cal) == nil {
				t.Fatal("setup: the event should not encode")
			}
			repairs, err := makeEncodable(cal, factsFixture)
			if err != nil {
				t.Fatalf("not repaired: %v", err)
			}
			if encodes(cal) != nil {
				t.Fatal("still does not encode")
			}
			if len(repairs) != 1 || repairs[0] != tc.repair {
				t.Fatalf("repairs = %v, want [%q]", repairs, tc.repair)
			}
			tc.check(t, cal)
			if got := ev(cal).Props.Get(ical.PropUID).Value; got == "" {
				t.Error("UID lost")
			}
			for _, r := range repairs {
				if strings.Contains(r, "Secret") || strings.Contains(r, "mailto") {
					t.Errorf("a repair label must not carry event content: %q", r)
				}
			}
		})
	}
}

func TestSeveralDefectsAreAllRepaired(t *testing.T) {
	cal := event("a")
	delete(cal.Props, ical.PropVersion)
	delete(ev(cal).Props, ical.PropDateTimeStamp)
	ev(cal).Props.Add(&ical.Prop{Name: ical.PropDateTimeStart, Value: "20260106T100000Z"})
	ev(cal).Props.Set(&ical.Prop{Name: ical.PropLocation, Value: "a\nb"})
	repairs, err := makeEncodable(cal, factsFixture)
	if err != nil || encodes(cal) != nil || len(repairs) != 4 {
		t.Fatalf("repairs=%v err=%v", repairs, err)
	}
}

func TestWhatCannotBeRepairedIsReportedNotHidden(t *testing.T) {
	cal := event("a")
	ev(cal).Children = append(ev(cal).Children, ical.NewComponent("VEVENT")) // a nested event is forbidden
	repairs, err := makeEncodable(cal, eventFacts{})
	if err == nil || !strings.Contains(err.Error(), "nested") {
		t.Fatalf("err=%v repairs=%v", err, repairs)
	}

	noUID := event("b")
	delete(ev(noUID).Props, ical.PropUID)
	if _, err := makeEncodable(noUID, eventFacts{}); err == nil {
		t.Fatal("a missing UID with nothing to take one from cannot be repaired, and must say so")
	}
}

func TestRepairingNeverLoopsForever(t *testing.T) {
	cal := event("a")
	// Many different defects at once: bounded by maxRepairs, and the loop ends either way.
	for i := 0; i < 40; i++ {
		ev(cal).Props.Add(&ical.Prop{Name: ical.PropSummary, Value: "x"})
	}
	done := make(chan struct{})
	go func() { makeEncodable(cal, factsFixture); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the repair loop did not end")
	}
}

// --- merging cards keeps every value ---

func TestMergingKeepsEveryValueOfARepeatedProperty(t *testing.T) {
	card := ical.Props{}
	card.Add(&ical.Prop{Name: "EXDATE", Value: "20260112T100000Z"})
	card.Add(&ical.Prop{Name: "EXDATE", Value: "20260119T100000Z"})
	card.Add(&ical.Prop{Name: "ATTENDEE", Value: "mailto:a@x"})
	card.Add(&ical.Prop{Name: "ATTENDEE", Value: "mailto:b@x"})
	card.Add(&ical.Prop{Name: "ATTENDEE", Value: "mailto:c@x"})
	card.Add(&ical.Prop{Name: "SUMMARY", Value: "s"})

	dst := ical.Props{}
	mergeProps(dst, card)
	if n := len(dst.Values("EXDATE")); n != 2 {
		t.Errorf("EXDATE: %d of 2 kept: excluded occurrences would reappear", n)
	}
	if n := len(dst.Values("ATTENDEE")); n != 3 {
		t.Errorf("ATTENDEE: %d of 3 kept", n)
	}
}

func TestMergingAfterAnotherCardReplacesAPropertyWholeWithoutDuplicates(t *testing.T) {
	shared := ical.Props{}
	shared.Add(&ical.Prop{Name: "UID", Value: "u"})
	shared.Add(&ical.Prop{Name: "DTSTAMP", Value: "20260101T000000Z"})
	shared.Add(&ical.Prop{Name: "ATTENDEE", Value: "mailto:old@x"})
	personal := ical.Props{}
	personal.Add(&ical.Prop{Name: "UID", Value: "u"}) // repeated by the second card
	personal.Add(&ical.Prop{Name: "ATTENDEE", Value: "mailto:a@x"})
	personal.Add(&ical.Prop{Name: "ATTENDEE", Value: "mailto:b@x"})

	dst := ical.Props{}
	mergeProps(dst, shared)
	mergeProps(dst, personal)
	if n := len(dst.Values("UID")); n != 1 {
		t.Errorf("UID duplicated: %d", n)
	}
	if v := dst.Values("ATTENDEE"); len(v) != 2 || v[0].Value != "mailto:a@x" {
		t.Errorf("the later card's attendees should replace the earlier ones: %+v", v)
	}
	if len(dst.Values("DTSTAMP")) != 1 {
		t.Error("a property only the first card had must stay")
	}
}

func TestMergedPropsDoNotAliasTheSource(t *testing.T) {
	src := ical.Props{}
	src.Add(&ical.Prop{Name: "EXDATE", Value: "1"})
	dst := ical.Props{}
	mergeProps(dst, src)
	dst["EXDATE"][0].Value = "changed"
	if src["EXDATE"][0].Value != "1" {
		t.Fatal("the merge shares memory with the decoded card")
	}
}

// --- the summary line ---

func TestServingSummaryIsOneLinePerKindNotPerEvent(t *testing.T) {
	logs := captureCacheLog(t)
	for i := 0; i < 300; i++ {
		noteServing([]string{"added the missing DTSTAMP to VEVENT"}, nil)
	}
	for i := 0; i < 12; i++ {
		noteServing([]string{"added the missing DTSTAMP to VEVENT", "dropped DURATION where DTEND is present"}, nil)
	}
	for i := 0; i < 5; i++ {
		noteServing(nil, errString("ical: failed to encode VEVENT: nested components are forbidden"))
	}
	logServing("cal")
	logServing("cal") // nothing left
	out := logs.String()
	if strings.Count(out, "\n") != 2 {
		t.Fatalf("want two summary lines, got:\n%s", out)
	}
	for _, want := range []string{"312 event(s)", "312x added the missing DTSTAMP", "12x dropped DURATION", "5 event(s)", "cannot be served"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
}

// --- caches written by earlier versions ---

func brokenEvent(uid string) *ical.Calendar {
	cal := event(uid)
	delete(ev(cal).Props, ical.PropDateTimeStamp)                                          // fixable
	ev(cal).Props.Add(&ical.Prop{Name: ical.PropDateTimeStart, Value: "20260106T100000Z"}) // fixable
	return cal
}

func TestARestoredCacheIsRepairedSoItsEventsCanBeServed(t *testing.T) {
	home(t)
	logs := captureCacheLog(t)
	saveCacheToDisk("cal", cacheWith(map[string]*ical.Calendar{"ok": event("ok"), "bad": brokenEvent("bad")}), testKey)

	cc := fresh()
	if !loadCacheFromDisk("cal", cc, testKey) || len(cc.objects) != 2 {
		t.Fatalf("loaded=%v objects=%d", cc.loaded, len(cc.objects))
	}
	for id, o := range cc.objects {
		if err := encodes(o.Data); err != nil {
			t.Errorf("%s still cannot be encoded after the restore: %v", id, err)
		}
	}
	out := logs.String()
	if !strings.Contains(out, "1 restored event(s) needed repair to be served") || !strings.Contains(out, "added the missing DTSTAMP") || !strings.Contains(out, "kept the first of several DTSTART") {
		t.Errorf("the repair must be reported:\n%s", out)
	}
	if strings.Contains(out, "cannot be served") {
		t.Errorf("nothing was beyond repair:\n%s", out)
	}
}

func TestARestoredEventBeyondRepairIsReportedNotDropped(t *testing.T) {
	home(t)
	logs := captureCacheLog(t)
	hopeless := event("h")
	ev(hopeless).Children = append(ev(hopeless).Children, ical.NewComponent("VEVENT"))
	saveCacheToDisk("cal", cacheWith(map[string]*ical.Calendar{"ok": event("ok"), "h": hopeless}), testKey)

	cc := fresh()
	if !loadCacheFromDisk("cal", cc, testKey) || len(cc.objects) != 2 {
		t.Fatalf("an event that cannot be served is still part of the calendar: objects=%d", len(cc.objects))
	}
	if out := logs.String(); !strings.Contains(out, "1 restored event(s) cannot be served") || !strings.Contains(out, "nested") {
		t.Errorf("log:\n%s", out)
	}
}

func TestTheDryRunSaysWhatWouldBeRepairedAndChangesNothing(t *testing.T) {
	home(t)
	dir := filepath.Dir(mustPath(t, "x"))
	hopeless := event("h")
	ev(hopeless).Children = append(ev(hopeless).Children, ical.NewComponent("VEVENT"))
	saveCacheToDisk("cal", cacheWith(map[string]*ical.Calendar{"ok": event("ok"), "bad": brokenEvent("bad"), "h": hopeless}), testKey)
	before := snapshotDir(t, dir)

	reports, err := CheckCacheDir(dir, func() (*[32]byte, error) { return testKey, nil })
	if err != nil || len(reports) != 1 {
		t.Fatalf("%v %v", reports, err)
	}
	r := reports[0]
	if r.Fixed != 1 || r.Unservable != 1 || !r.Complete() {
		t.Errorf("report = %+v", r)
	}
	out := r.String()
	for _, want := range []string{"1 event(s) could not be sent to a client as stored and are repaired", "1 event(s) cannot be sent to a client at all"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Secret event") {
		t.Errorf("event text in the report:\n%s", out)
	}
	if snapshotDir(t, dir) != before {
		t.Fatal("the dry run changed the directory")
	}
}
