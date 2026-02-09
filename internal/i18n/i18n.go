// Package i18n provides lightweight translation using embedded JSON locale files.
package i18n

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
)

//go:embed locales/*.json
var localeFS embed.FS

// Translator resolves translated template strings for a given language.
type Translator struct {
	lang     string
	msgs     map[string]string
	fallback map[string]string // always English
}

// New creates a Translator for the given language code.
// If the language is not found, it falls back to English.
func New(lang string) (*Translator, error) {
	en, err := loadLocale("en")
	if err != nil {
		return nil, fmt.Errorf("i18n: loading en: %w", err)
	}

	msgs := en
	if lang != "en" {
		m, err := loadLocale(lang)
		if err != nil {
			// Unknown language: use English entirely.
			msgs = en
		} else {
			msgs = m
		}
	}

	return &Translator{
		lang:     lang,
		msgs:     msgs,
		fallback: en,
	}, nil
}

// T renders the template for key with the given data.
// Fallback order: lang[key] -> en[key] -> key itself.
func (t *Translator) T(key string, data any) string {
	tmplStr := t.resolve(key)
	return renderTemplate(tmplStr, data)
}

// Lang returns the resolved language code.
func (t *Translator) Lang() string {
	return t.lang
}

func (t *Translator) resolve(key string) string {
	if s, ok := t.msgs[key]; ok {
		return s
	}
	if s, ok := t.fallback[key]; ok {
		return s
	}
	return key
}

func loadLocale(lang string) (map[string]string, error) {
	data, err := localeFS.ReadFile("locales/" + lang + ".json")
	if err != nil {
		return nil, err
	}
	var msgs map[string]string
	if err := json.Unmarshal(data, &msgs); err != nil {
		return nil, fmt.Errorf("i18n: parsing %s.json: %w", lang, err)
	}
	return msgs, nil
}

func renderTemplate(tmplStr string, data any) string {
	// Fast path: no template delimiters, return as-is.
	if !strings.Contains(tmplStr, "{{") {
		return tmplStr
	}

	tmpl, err := template.New("").Parse(tmplStr)
	if err != nil {
		return tmplStr
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return tmplStr
	}
	return buf.String()
}
