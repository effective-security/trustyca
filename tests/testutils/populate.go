package testutils

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/effective-security/x/values"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
)

// PopulateObject populates obj with random values
func PopulateObject(obj any, attr string) {
	v := reflect.ValueOf(obj)
	if v.Kind() != reflect.Pointer {
		logger.Panicf("not a pointer: kind=%v, type=%v", v.Kind(), v.Type())
	}
	v = v.Elem()
	typ := v.Type()
	if v.Kind() != reflect.Struct {
		logger.Panicf("not a struct: kind=%v, type=%v", v.Kind(), typ)
	}

	for i := 0; i < typ.NumField(); i++ {
		sf := typ.Field(i)
		vf := v.Field(i)
		typ := vf.Type().String()
		switch sf.Type.Kind() {
		case reflect.String:
			tagValue := sf.Tag.Get(attr)
			fieldName := fmt.Sprintf("%s-%d", values.StringsCoalesce(fieldNameFromTag(tagValue), sf.Name), i+1)
			vf.SetString(fieldName)
		case reflect.Bool:
			vf.SetBool(true)
		case reflect.Int:
			vf.SetInt(int64(i + 1))
		case reflect.Float64:
			vf.SetFloat(float64(i + 1))
		case reflect.Pointer:
			if typ == "*time.Time" {
				vf.Set(reflect.ValueOf(time.Now()))
			} else {
				logger.KV(xlog.NOTICE, "unsupported", sf.Name, "type", typ)
			}
		//case reflect.Slice:
		// TODO:
		// vf.Set(reflect.ValueOf(r.Strings(fieldName)))
		default:
			switch typ {
			case "xdb.ID":
				// Warning: ID can't be populated
				vf.Set(reflect.ValueOf(xdb.NewID(uint64(time.Now().UTC().Unix()))))
			case "xdb.Time":
				vf.Set(reflect.ValueOf(xdb.Now()))
			default:
				logger.KV(xlog.NOTICE, "unsupported", sf.Name, "type", typ)
			}
		}
	}
}

func fieldNameFromTag(tag string) string {
	tokens := strings.Split(tag, ",")
	for _, t := range tokens {
		if strings.HasPrefix(t, "fieldName=") {
			return t[10:]
		}
	}
	return tokens[0]
}
