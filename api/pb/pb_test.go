package pb_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/stretchr/testify/assert"
)

func TestIDPFromString(t *testing.T) {
	assert.Equal(t, pb.IDP_Google, pb.IDPFromString("google"))
	assert.Equal(t, pb.IDP_Google, pb.IDPFromString("1"))
	assert.Equal(t, pb.IDP_Github, pb.IDPFromString("github"))
	assert.Equal(t, pb.IDP_Github, pb.IDPFromString("2"))
	assert.Equal(t, pb.IDP_Gitlab, pb.IDPFromString("gitlab"))
	assert.Equal(t, pb.IDP_Gitlab, pb.IDPFromString("3"))
	assert.Equal(t, pb.IDP_Local, pb.IDPFromString("local"))
	assert.Equal(t, pb.IDP_Local, pb.IDPFromString("1000"))
}

func TestIDPFromSlice(t *testing.T) {
	assert.Equal(t, []pb.IDP_Enum{pb.IDP_Google, pb.IDP_Github, pb.IDP_Gitlab, pb.IDP_Local}, pb.IDPFromSlice([]string{"google", "github", "gitlab", "local"}))
	assert.Equal(t, []pb.IDP_Enum{pb.IDP_Google, pb.IDP_Github, pb.IDP_Gitlab, pb.IDP_Local}, pb.IDPFromSlice([]string{"1", "2", "3", "1000"}))
}

func TestFindKVPair(t *testing.T) {
	assert.Equal(t, "value", pb.FindKVPair([]*pb.KVPair{{Key: "key", Value: "value"}}, "key"))
	assert.Equal(t, "", pb.FindKVPair([]*pb.KVPair{{Key: "key", Value: "value"}}, "not_found"))
}

func TestMapFromKVPair(t *testing.T) {
	assert.Equal(t, map[string]string{"key": "value"}, pb.MapFromKVPair([]*pb.KVPair{{Key: "key", Value: "value"}}))
}

func TestFlatMap(t *testing.T) {
	assert.Equal(t, []*pb.KVPair{{Key: "key", Value: "value"}}, pb.FlatMap(map[string]string{"key": "value"}))
}
