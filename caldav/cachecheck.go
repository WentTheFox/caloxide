package caldav

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CacheFileReport describes one on-disk calendar cache, as the server would read it.
type CacheFileReport struct {
	File             string         `json:"file"`
	Calendar         string         `json:"calendar"`
	Bytes            int64          `json:"bytes"`
	Entries          int            `json:"entries"`
	Want             int            `json:"want"`
	Restored         int            `json:"restored"`
	FromTree         int            `json:"from_tree"`
	FromText         int            `json:"from_text"`
	Repaired         int            `json:"repaired"`
	Fixed            int            `json:"fixed"`      // events a client could not be sent as stored, repaired on restore
	Unservable       int            `json:"unservable"` // events that still cannot be sent
	SplitSeries      int            `json:"split_series"`
	SplitEvents      int            `json:"split_events"`
	EditedOccurences int            `json:"edited_occurrences"`
	SharedAddresses  int            `json:"shared_addresses"`
	SharedEvents     int            `json:"shared_events"`
	Failed           map[string]int `json:"failed,omitempty"`
	FixedKinds       map[string]int `json:"fixed_kinds,omitempty"`
	UnservableKind   map[string]int `json:"unservable_kinds,omitempty"`
	Sealed           bool           `json:"sealed"`
	Unusable         string         `json:"unusable,omitempty"` // the file could not be read at all
}

// CheckCacheDir reads every calendar cache in dir and reports what reading it back gives.
// It is a dry run in the strict sense: it only reads, never writes, never contacts
// Proton, and its output contains counts and error classes, never event text.
//
// Sealed caches need the key. keyFn is called at most once, the first time a sealed file is
// met (so it can ask for the bridge password then), and may be nil.
func CheckCacheDir(dir string, keyFn func() (*[32]byte, error)) ([]CacheFileReport, error) {
	var key *[32]byte
	var keyErr error
	haveKey := false
	paths, err := filepath.Glob(filepath.Join(dir, "calcache-*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var out []CacheFileReport
	for _, p := range paths {
		rep := CacheFileReport{File: filepath.Base(p), Failed: map[string]int{}}
		rep.Calendar = strings.TrimSuffix(strings.TrimPrefix(rep.File, "calcache-"), ".json")
		raw, err := os.ReadFile(p)
		if err != nil {
			rep.Unusable = err.Error()
			out = append(out, rep)
			continue
		}
		rep.Bytes = int64(len(raw))
		// Is it sealed? Then the key is needed, and asked for once.
		var env sealedFile
		if json.Unmarshal(raw, &env) == nil && env.Format == sealedFormat {
			rep.Sealed = true
			if !haveKey {
				haveKey = true
				if keyFn != nil {
					key, keyErr = keyFn()
				} else {
					keyErr = errNeedKey
				}
			}
			if key == nil {
				rep.Unusable = "encrypted, and it cannot be opened here: " + errorClass(keyErr)
				out = append(out, rep)
				continue
			}
		}
		pc, _, err := openCacheFile(raw, key)
		if err != nil {
			rep.Unusable = errorClass(err)
			out = append(out, rep)
			continue
		}
		_, r := restoreObjects(pc)
		rep.Entries, rep.Want, rep.Restored = r.Entries, r.Want, r.Restored
		rep.FromTree, rep.FromText, rep.Repaired, rep.Failed = r.FromTree, r.FromText, r.Repaired, r.Failed
		rep.Fixed, rep.Unservable = r.Fixed, r.Unservable
		rep.SharedAddresses, rep.SharedEvents = r.SharedAddresses, r.SharedEvents
		rep.SplitSeries, rep.SplitEvents, rep.EditedOccurences = r.SplitSeries, r.SplitEvents, r.EditedOccurences
		rep.FixedKinds, rep.UnservableKind = r.FixedKinds, r.UnservableKind
		out = append(out, rep)
	}
	return out, nil
}

// Complete reports whether the server would trust this cache without fetching it again.
func (r CacheFileReport) Complete() bool { return r.Unusable == "" && r.Restored == r.Want }

// String renders the report for a terminal.
func (r CacheFileReport) String() string {
	short := r.Calendar
	if len(short) > 12 {
		short = short[:12] + "…"
	}
	var sb strings.Builder
	switch {
	case r.Unusable != "":
		fmt.Fprintf(&sb, "%s  UNUSABLE: %s\n    The server ignores this file and loads the calendar from Proton.\n", short, r.Unusable)
		if r.Sealed {
			sb.WriteString("    (An encrypted cache opens only with the bridge password it was saved under.)\n")
		}
	case r.Complete():
		enc := "encrypted"
		if !r.Sealed {
			enc = "NOT encrypted"
		}
		fmt.Fprintf(&sb, "%s  complete, %s: %s of %s events read back (%s as structure, %s as text", short, enc,
			thousands(r.Restored), thousands(r.Want), thousands(r.FromTree), thousands(r.FromText))
		if r.Repaired > 0 {
			fmt.Fprintf(&sb, ", %s needed repair", thousands(r.Repaired))
		}
		sb.WriteString(")\n")
		if !r.Sealed {
			sb.WriteString("    It is encrypted the next time the calendar is saved.\n")
		}
		if r.FromText > 0 {
			sb.WriteString("    Text entries are rewritten as structure the next time the calendar is loaded in full.\n")
		}
	default:
		fmt.Fprintf(&sb, "%s  INCOMPLETE: %s of %s events read back (%s missing)\n", short,
			thousands(r.Restored), thousands(r.Want), thousands(r.Want-r.Restored))
		sb.WriteString("    The server will not trust this file: it loads the calendar from Proton in full and\n    saves it again in the new format. Nothing is written to Proton.\n")
		if len(r.Failed) > 0 {
			fmt.Fprintf(&sb, "    Why: %s\n", failureSummary(r.Failed))
		} else {
			sb.WriteString("    Why: the file holds fewer events than it says it had been given to save.\n")
		}
	}
	if r.Unusable == "" {
		if r.Fixed > 0 {
			fmt.Fprintf(&sb, "    %s event(s) could not be sent to a client as stored and are repaired when loaded: %s\n", thousands(r.Fixed), countsSummary(r.FixedKinds))
		}
		if r.SplitSeries > 0 {
			fmt.Fprintf(&sb, "    %s recurring series have edited occurrences (%s events in all, %s edited occurrences), each served as one resource\n",
				thousands(r.SplitSeries), thousands(r.SplitEvents), thousands(r.EditedOccurences))
		}
		if r.SharedAddresses > 0 {
			fmt.Fprintf(&sb, "    %s place(s) in a series are claimed by %s events: only one of each can be shown\n", thousands(r.SharedAddresses), thousands(r.SharedEvents))
		}
		if r.Unservable > 0 {
			fmt.Fprintf(&sb, "    %s event(s) cannot be sent to a client at all (they do not encode as iCalendar): %s\n", thousands(r.Unservable), countsSummary(r.UnservableKind))
		}
	}
	return sb.String()
}
