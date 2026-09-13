package pb

import (
	"sort"
	"strings"
)

//go:generate mockgen -source=auth_grpc.pb.go -destination=../../mocks/mockpb/auth_mock.gen.go -package mockpb
//go:generate mockgen -source=status_grpc.pb.go -destination=../../mocks/mockpb/status_mock.gen.go -package mockpb
//go:generate mockgen -source=orgs_grpc.pb.go -destination=../../mocks/mockpb/orgs_mock.gen.go -package mockpb
//go:generate mockgen -source=ca_grpc.pb.go -destination=../../mocks/mockpb/ca_mock.gen.go -package mockpb
//go:generate mockgen -source=cis_grpc.pb.go -destination=../../mocks/mockpb/cis_mock.gen.go -package mockpb

// IDPFromString converts a string to an IDP_Enum.
func IDPFromString(s string) IDP_Enum {
	if s == "" {
		return IDP_Undefined
	}
	if p, ok := IDP_Enum_Value[s]; ok {
		return p
	}
	switch strings.ToLower(s) {
	case "google", "1":
		return IDP_Google
	case "github", "2":
		return IDP_Github
	case "gitlab", "3":
		return IDP_Gitlab
	case "local", "1000":
		return IDP_Local
	}
	return IDP_Undefined
}

// IDPFromSlice converts a slice of strings to a slice of IDP_Enum
func IDPFromSlice(s []string) []IDP_Enum {
	if len(s) == 0 {
		return nil
	}
	providers := make([]IDP_Enum, 0, len(s))
	for _, provider := range s {
		providers = append(providers, IDPFromString(provider))
	}
	return providers
}

func FindKVPair(list []*KVPair, key string) string {
	for _, kv := range list {
		if kv.Key == key {
			return kv.Value
		}
	}
	return ""
}

func MapFromKVPair(list []*KVPair) map[string]string {
	if len(list) == 0 {
		return nil
	}
	res := make(map[string]string, len(list))
	for _, kv := range list {
		if kv.Key != "" && kv.Value != "" {
			res[kv.Key] = kv.Value
		}
	}
	return res
}

func FlatMap(meta map[string]string) []*KVPair {
	count := len(meta)
	if count == 0 {
		return nil
	}
	res := make([]*KVPair, 0, count)

	for k, v := range meta {
		if v != "" {
			res = append(res, &KVPair{Key: k, Value: v})
		}
	}

	// make deterministic
	sort.Slice(res, func(i, j int) bool {
		return res[i].Key < res[j].Key
	})

	return res
}

func FlatKVSet(meta map[string][]string) []*KVSet {
	count := len(meta)
	if count == 0 {
		return nil
	}
	res := make([]*KVSet, 0, count)

	for k, v := range meta {
		if len(v) > 0 {
			res = append(res, &KVSet{Key: k, Values: v})
		}
	}

	// make deterministic
	sort.Slice(res, func(i, j int) bool {
		return res[i].Key < res[j].Key
	})

	return res
}
