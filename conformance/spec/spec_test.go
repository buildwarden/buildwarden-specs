package spec

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

func TestRequirements(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		want    []string
		wantErr string
	}{
		{name: "none", doc: "# t\n\nprose CLAIM-1 only\n", want: nil},
		{
			name: "paragraphs and list items",
			doc: "**CLAIM-1.** The relay MUST.\n\n- **CLAIM-2.** A claimant MUST.\n" +
				"3. **CLAIM-3.** ordered\n   **CLAIM-4.** indented\n* **CLAIM-10.** star\n",
			want: []string{"CLAIM-1", "CLAIM-2", "CLAIM-3", "CLAIM-4", "CLAIM-10"},
		},
		{name: "a reference in prose states nothing", doc: "See **CLAIM-1.** above.\nas CLAIM-2 says\n", want: nil},
		{name: "bold without the full stop states nothing", doc: "**CLAIM-1** text\n", want: nil},
		{name: "indented code is not a fence", doc: "    **CLAIM-1.** four spaces\n", want: nil},
		{
			name: "fenced blocks state nothing",
			doc:  "```\n**CLAIM-1.** example\n```\n~~~\n**CLAIM-2.** example\n```\n~~~\n**CLAIM-3.** real\n",
			want: []string{"CLAIM-3"},
		},
		{name: "unclosed fence", doc: "```\n**CLAIM-1.** x\n", wantErr: "not closed"},
		{name: "leading zero", doc: "**CLAIM-07.** x\n", wantErr: `"CLAIM-07" is not a requirement identifier`},
		{name: "lower case", doc: "**claim-7.** x\n", wantErr: "is not a requirement identifier"},
		{name: "another prefix", doc: "**GUEST-1.** x\n", wantErr: "does not have this specification's prefix CLAIM"},
		{name: "stated twice", doc: "**CLAIM-1.** x\n\n**CLAIM-1.** y\n", wantErr: "line 3: CLAIM-1 is stated again (first on line 1)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Requirements([]byte(tt.doc), "CLAIM")
			checkErr(t, err, tt.wantErr)
			if tt.wantErr == "" && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseList(t *testing.T) {
	tests := []struct {
		name    string
		list    string
		want    []Unchecked
		wantErr string
	}{
		{name: "empty", list: "", want: nil},
		{name: "comments and blanks", list: "# header\n\n  \n# more\n", want: nil},
		{
			name: "entries",
			list: "INIT-1 its suite is S2's\r\nINIT-2   spaced reason  \n",
			want: []Unchecked{{"INIT-1", "its suite is S2's"}, {"INIT-2", "spaced reason"}},
		},
		{name: "no reason", list: "INIT-1\n", wantErr: "line 1: INIT-1 has no reason"},
		{name: "blank reason", list: "INIT-1   \n", wantErr: "INIT-1 has no reason"},
		{name: "malformed", list: "INIT-0 x\n", wantErr: "is not a requirement identifier"},
		{name: "another prefix", list: "CLAIM-1 x\n", wantErr: "prefix INIT"},
		{name: "listed twice", list: "INIT-1 a\nINIT-1 b\n", wantErr: "line 2: INIT-1 is listed again (first on line 1)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseList([]byte(tt.list), "INIT")
			checkErr(t, err, tt.wantErr)
			if tt.wantErr == "" && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestChangelogVersion(t *testing.T) {
	tests := []struct {
		name, changelog, want, wantErr string
	}{
		{name: "head", changelog: "# Changelog\n\ntext\n\n## v0.2.0\n\n- b\n\n## v0.1.0\n", want: "v0.2.0"},
		{name: "trailing spaces", changelog: "## v1.10.0  \n", want: "v1.10.0"},
		{name: "none", changelog: "# Changelog\n", wantErr: "no version heading"},
		{name: "unreleased heading", changelog: "## Unreleased\n## v0.1.0\n", wantErr: `"## Unreleased"`},
		{name: "no v", changelog: "## 0.1.0\n", wantErr: "want ## vX.Y.Z"},
		{name: "leading zero", changelog: "## v0.01.0\n", wantErr: "want ## vX.Y.Z"},
		{name: "prerelease", changelog: "## v0.1.0-rc1\n", wantErr: "want ## vX.Y.Z"},
		{name: "text after the version", changelog: "## v0.1.0 (draft)\n", wantErr: "want ## vX.Y.Z"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ChangelogVersion([]byte(tt.changelog))
			checkErr(t, err, tt.wantErr)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	files := fstest.MapFS{
		"v1.md":        {Data: []byte("# x\n\n**COLLIN-1.** a\n\n**COLLIN-2.** b\n")},
		ChangelogFile:  {Data: []byte("# Changelog\n\n## v0.3.1\n")},
		ListFile:       {Data: []byte("# h\nCOLLIN-2 needs a person\n")},
		"v1.openapi.x": {Data: []byte("ignored")},
	}
	s := Spec{Directory: "collector-inputs", Prefix: "COLLIN", Document: "v1.md", Files: files}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	want := Loaded{
		Version:      "v0.3.1",
		Requirements: []string{"COLLIN-1", "COLLIN-2"},
		Unchecked:    []Unchecked{{"COLLIN-2", "needs a person"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}

	for _, missing := range []string{"v1.md", ChangelogFile, ListFile} {
		t.Run("without "+missing, func(t *testing.T) {
			partial := fstest.MapFS{}
			for name, f := range files {
				if name != missing {
					partial[name] = f
				}
			}
			s.Files = partial
			_, err := s.Load()
			checkErr(t, err, "collector-inputs: open "+missing)
		})
	}
	t.Run("a bad file names itself", func(t *testing.T) {
		bad := fstest.MapFS{}
		for name, f := range files {
			bad[name] = f
		}
		bad[ListFile] = &fstest.MapFile{Data: []byte("COLLIN-1\n")}
		s.Files = bad
		_, err := s.Load()
		checkErr(t, err, "collector-inputs/not-machine-checked.txt: line 1: COLLIN-1 has no reason")
	})
}

func checkErr(t *testing.T, err error, want string) {
	t.Helper()
	switch {
	case want == "" && err != nil:
		t.Fatalf("unexpected error: %v", err)
	case want != "" && err == nil:
		t.Fatalf("no error, want one containing %q", want)
	case want != "" && !strings.Contains(err.Error(), want):
		t.Fatalf("error %q does not contain %q", err, want)
	}
}
