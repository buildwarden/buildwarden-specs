package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/buildwarden/buildwarden-specs/conformance/internal/cbor"
)

// EnvironmentLimit is the largest environment payload a relay accepts
// (CLAIM-53, COLLOUT-31).
const EnvironmentLimit = 1 << 20

// environmentType checks a claim's environment as CLAIM-28 states it and
// returns its type. A failure here fails the relay's start (CLAIM-50).
//
// Where CLAIM-28 lets a relay take a metadata of null or undefined as an
// empty map, accept a tag on the map, or keep the last of repeated keys,
// this one does none of these: the metadata must be one CBOR map with text
// keys, given once each, and nothing after it.
func environmentType(env *Environment) (string, error) {
	if len(env.Payload) == 0 {
		return "", errors.New("environment: the payload is empty")
	}
	if len(env.Payload) > EnvironmentLimit {
		return "", fmt.Errorf("environment: the payload is %d bytes, over %d", len(env.Payload), EnvironmentLimit)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(env.Payload, &obj); err != nil || obj == nil {
		return "", errors.New("environment: the payload is not a JSON object")
	}
	typ, err := payloadType(obj)
	if err != nil {
		return "", err
	}
	if env.Type != "" && env.Type != typ {
		return "", fmt.Errorf("environment: type %q is not the payload's type %q", env.Type, typ)
	}
	if _, err := cbor.DecodeMap(env.Metadata); err != nil {
		return "", fmt.Errorf("environment: the metadata is not one CBOR map: %w", err)
	}
	return typ, nil
}

// payloadType is the type a payload names: its member type, or
// oci-image/v1 for a payload that has none and is an image's manifest or
// index.
func payloadType(obj map[string]json.RawMessage) (string, error) {
	if raw, ok := obj["type"]; ok {
		var s string
		if json.Unmarshal(raw, &s) != nil || s == "" {
			return "", errors.New("environment: the payload's type is not a non-empty string")
		}
		return s, nil
	}
	if _, ok := obj["schemaVersion"]; ok {
		_, layers := obj["layers"]
		_, manifests := obj["manifests"]
		var media string
		if raw, ok := obj["mediaType"]; ok && json.Unmarshal(raw, &media) == nil {
			if strings.Contains(media, "manifest") || strings.Contains(media, "image.index") {
				return "oci-image/v1", nil
			}
		}
		if layers || manifests {
			return "oci-image/v1", nil
		}
	}
	return "", errors.New("environment: the payload names no type")
}
