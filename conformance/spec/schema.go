package spec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Validate reports whether body is one JSON value that validates against the
// specification's schema file, a file of Files such as
// "v1.identity.schema.json". Every schema file of Files is loaded, by its
// $id, so that one may refer to another; nothing is fetched from elsewhere.
func (s Spec) Validate(file string, body []byte) error {
	sch, err := s.schema(file)
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("the body is not one JSON value: %w", err)
	}
	if err := sch.Validate(inst); err != nil {
		return fmt.Errorf("the body does not validate against %s/%s: %w", s.Directory, file, err)
	}
	return nil
}

func (s Spec) schema(file string) (*jsonschema.Schema, error) {
	files, err := fs.Glob(s.Files, "*.schema.json")
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(noLoader{})
	want := ""
	for _, name := range files {
		b, err := fs.ReadFile(s.Files, name)
		if err != nil {
			return nil, err
		}
		var head struct {
			ID string `json:"$id"`
		}
		if err := json.Unmarshal(b, &head); err != nil || head.ID == "" {
			return nil, fmt.Errorf("%s/%s has no $id", s.Directory, name)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("%s/%s: %w", s.Directory, name, err)
		}
		if err := c.AddResource(head.ID, doc); err != nil {
			return nil, fmt.Errorf("%s/%s: %w", s.Directory, name, err)
		}
		if name == file {
			want = head.ID
		}
	}
	if want == "" {
		return nil, fmt.Errorf("%s has no schema file %s (it has %s)", s.Directory, file, strings.Join(files, ", "))
	}
	sch, err := c.Compile(want)
	if err != nil {
		return nil, fmt.Errorf("%s/%s: %w", s.Directory, file, err)
	}
	return sch, nil
}

// noLoader refuses every schema that is not one of the specification's own
// files, so that validating never reaches the network.
type noLoader struct{}

func (noLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("%s is not a schema file of this specification", url)
}
