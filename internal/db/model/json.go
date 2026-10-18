package model

import (
	"database/sql/driver"
	"encoding/json"

	"github.com/cockroachdb/errors"
)

// emptyJSON is the value of an empty NOT NULL jsonb column
const emptyJSON = "{}"

// JSON is the raw value of a jsonb column that holds a nested document, such
// as issuer.config (pb.IssuerConfig) and certificate_profile.config
// (pb.CertProfile), which xdb.Metadata (a flat string map) cannot represent.
// An empty value is written as the empty object, because the config columns
// are NOT NULL; a SQL NULL is read as an empty value.
type JSON json.RawMessage

// MarshalJSONValue encodes v as a JSON column value.
// pb messages encode with their generated MarshalJSON (protojson).
func MarshalJSONValue(v any) (JSON, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to marshal JSON value")
	}
	return JSON(b), nil
}

// Unmarshal decodes the column value into v; an empty value leaves v unchanged
func (j JSON) Unmarshal(v any) error {
	if j.IsEmpty() {
		return nil
	}
	err := json.Unmarshal([]byte(j), v)
	if err != nil {
		return errors.WithMessage(err, "unable to unmarshal JSON value")
	}
	return nil
}

// IsEmpty returns true when the value holds no document, or the empty object
func (j JSON) IsEmpty() bool {
	return len(j) == 0 || string(j) == emptyJSON
}

// String returns the JSON text
func (j JSON) String() string {
	if len(j) == 0 {
		return emptyJSON
	}
	return string(j)
}

// MarshalJSON implements json.Marshaler, so the model embeds the document
// rather than a base64 string
func (j JSON) MarshalJSON() ([]byte, error) {
	if len(j) == 0 {
		return []byte(nullJSON), nil
	}
	return []byte(j), nil
}

// nullJSON is the JSON null literal, read as an empty value
const nullJSON = "null"

// UnmarshalJSON implements json.Unmarshaler; null is an empty value
func (j *JSON) UnmarshalJSON(data []byte) error {
	if j == nil {
		return errors.New("JSON: UnmarshalJSON on nil pointer")
	}
	if string(data) == nullJSON {
		*j = nil
		return nil
	}
	*j = append((*j)[0:0], data...)
	return nil
}

// Scan implements the sql.Scanner interface
func (j *JSON) Scan(value any) error {
	switch v := value.(type) {
	case nil:
		*j = nil
	case []byte:
		*j = append(JSON(nil), v...)
	case string:
		*j = JSON(v)
	default:
		return errors.Errorf("unsupported scan type for JSON: %T", value)
	}
	return nil
}

// Value implements the driver.Valuer interface
func (j JSON) Value() (driver.Value, error) {
	if len(j) == 0 {
		return emptyJSON, nil
	}
	return string(j), nil
}
