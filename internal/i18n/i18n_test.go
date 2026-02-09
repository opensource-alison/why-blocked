package i18n

import "testing"

func TestNew_English(t *testing.T) {
	tr, err := New("en")
	if err != nil {
		t.Fatalf("New(en) error = %v", err)
	}
	if tr.Lang() != "en" {
		t.Errorf("Lang() = %q, want %q", tr.Lang(), "en")
	}
}

func TestT_KnownKey_Japanese(t *testing.T) {
	tr, err := New("ja")
	if err != nil {
		t.Fatalf("New(ja) error = %v", err)
	}
	got := tr.T("label.evidence", nil)
	if got != "証拠:" {
		t.Errorf("T(label.evidence) = %q, want %q", got, "証拠:")
	}
}

func TestT_KnownKey_Korean(t *testing.T) {
	tr, err := New("ko")
	if err != nil {
		t.Fatalf("New(ko) error = %v", err)
	}
	got := tr.T("label.fix", nil)
	if got != "수정 (최소):" {
		t.Errorf("T(label.fix) = %q, want %q", got, "수정 (최소):")
	}
}

func TestT_UnknownLang_FallsBackToEnglish(t *testing.T) {
	tr, err := New("fr")
	if err != nil {
		t.Fatalf("New(fr) error = %v", err)
	}
	got := tr.T("label.evidence", nil)
	if got != "Evidence:" {
		t.Errorf("T(label.evidence) = %q, want %q", got, "Evidence:")
	}
}

func TestT_MissingKey_ReturnsKey(t *testing.T) {
	tr, err := New("en")
	if err != nil {
		t.Fatalf("New(en) error = %v", err)
	}
	got := tr.T("no.such.key", nil)
	if got != "no.such.key" {
		t.Errorf("T(no.such.key) = %q, want %q", got, "no.such.key")
	}
}

func TestT_TemplateInterpolation(t *testing.T) {
	tr, err := New("en")
	if err != nil {
		t.Fatalf("New(en) error = %v", err)
	}

	data := map[string]any{"Summary": "blocked by policy"}
	got := tr.T("output.reason", data)
	want := "WHY: blocked by policy"
	if got != want {
		t.Errorf("T(output.reason) = %q, want %q", got, want)
	}
}

func TestT_TemplateInterpolation_Violations(t *testing.T) {
	tr, err := New("zh")
	if err != nil {
		t.Fatalf("New(zh) error = %v", err)
	}

	data := map[string]any{"Count": 3}
	got := tr.T("section.violations", data)
	want := "违规 (3):"
	if got != want {
		t.Errorf("T(section.violations) = %q, want %q", got, want)
	}
}

func TestT_MissingKey_InNonEnglish_FallsBackToEnglish(t *testing.T) {
	// Simulate a locale that is missing a key by using a valid lang
	// and verifying a key present in en but hypothetically missing
	// would fall back. Since all locales currently have the same keys,
	// we test the mechanism via an unknown key which returns the key itself.
	tr, err := New("ja")
	if err != nil {
		t.Fatalf("New(ja) error = %v", err)
	}

	// Known key in both ja and en — should use ja.
	got := tr.T("label.what", nil)
	if got != "内容:" {
		t.Errorf("T(label.what) = %q, want %q", got, "内容:")
	}

	// Unknown key — falls through ja, then en, then returns key.
	got = tr.T("nonexistent.key", nil)
	if got != "nonexistent.key" {
		t.Errorf("T(nonexistent.key) = %q, want %q", got, "nonexistent.key")
	}
}

func TestAllLocalesLoad(t *testing.T) {
	for _, lang := range []string{"en", "ko", "ja", "zh", "es"} {
		t.Run(lang, func(t *testing.T) {
			tr, err := New(lang)
			if err != nil {
				t.Fatalf("New(%s) error = %v", lang, err)
			}
			// Every locale must have at least the core keys.
			for _, key := range []string{
				"output.reason",
				"output.status",
				"section.violations",
				"label.evidence",
				"label.fix",
			} {
				got := tr.T(key, nil)
				if got == key {
					t.Errorf("T(%q) returned key itself for lang %s", key, lang)
				}
			}
		})
	}
}
