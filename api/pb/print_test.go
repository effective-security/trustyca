package pb_test

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	sync "sync"
	"testing"
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/x/format"
	"github.com/effective-security/x/print"
)

func TestPrintPb(t *testing.T) {
	t.Parallel()
	pb.RegisterPrintOnce()

	lock := sync.Mutex{}
	results := []struct {
		name string
		out  string
	}{}

	t.Cleanup(func() {
		sort.Slice(results, func(i, j int) bool {
			return results[i].name < results[j].name
		})
		_ = os.Mkdir("testdata", 0755)
		f, _ := os.Create(filepath.Join("testdata", "print.txt"))
		for _, r := range results {
			_, _ = f.WriteString("\n- ")
			_, _ = f.WriteString(r.name)
			_, _ = f.WriteString(":\n\n")
			_, _ = f.WriteString(r.out)
			_, _ = f.WriteString("\n")
		}
		_ = f.Close()
	})

	capturePrint := func(val any) {
		w := bytes.NewBuffer([]byte{})
		print.Print(w, val)
		out := w.String()

		typ := reflect.TypeOf(val)
		name := ""
		if typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
			name = typ.Name()
		} else if typ.Kind() == reflect.Slice {
			elem := typ.Elem()
			if elem.Kind() == reflect.Pointer {
				elem = elem.Elem()
			}
			name = "[]" + elem.Name()
		} else {
			name = typ.Name()
		}

		lock.Lock()
		results = append(results, struct {
			name string
			out  string
		}{name: name, out: out})
		lock.Unlock()
	}
	format.NowFunc = func() time.Time {
		return time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	}
	defer func() {
		format.NowFunc = time.Now
	}()

	t.Run("KVPair", func(t *testing.T) {
		t.Parallel()
		kv := &pb.KVPair{
			Key:   "test",
			Value: "test",
		}
		capturePrint(kv)
	})

	t.Run("LoginInfo", func(t *testing.T) {
		t.Parallel()
		loginInfo := &pb.LoginInfo{
			ID:    "1",
			Name:  "Test User",
			Email: "test@example.com",
		}
		capturePrint(loginInfo)

		loginInfos := []*pb.LoginInfo{loginInfo}
		capturePrint(loginInfos)
	})

	t.Run("CallerStatusResponse", func(t *testing.T) {
		t.Parallel()
		callerStatusResponse := &pb.CallerStatusResponse{
			Subject: "test",
			Role:    "Admin",
			Claims: []*pb.KVPair{
				{
					Key:   "test",
					Value: "test",
				},
				{
					Key:   "test2",
					Value: "test2",
				},
			},
		}
		capturePrint(callerStatusResponse)
	})

	t.Run("Membership", func(t *testing.T) {
		t.Parallel()
		membership := &pb.Membership{
			ID:     "1",
			UserID: "3",
			Role:   pb.Role_Admin,
		}
		capturePrint(membership)

		invite := &pb.Invite{
			ID:    "2",
			Email: "test@example.com",
			Role:  pb.Role_Admin,
		}
		capturePrint(invite)

		value := &pb.MembersResponse{
			Memberships: []*pb.Membership{membership},
			Invites:     []*pb.Invite{invite},
		}
		capturePrint(value)

		value2 := &pb.UserMemberships{
			Memberships: []*pb.Membership{membership},
		}
		capturePrint(value2)
	})

	t.Run("AddMemberResponse", func(t *testing.T) {
		t.Parallel()

		invite := &pb.Invite{
			ID:    "2",
			Email: "test@example.com",
			Role:  pb.Role_Admin,
		}
		membership := &pb.Membership{
			ID:     "1",
			UserID: "3",
			Role:   pb.Role_Admin,
		}

		response := &pb.AddMemberResponse{
			Membership: membership,
			Invite:     invite,
		}
		capturePrint(response)
	})

	t.Run("Org", func(t *testing.T) {
		t.Parallel()
		org := &pb.Org{
			ID:     "1",
			Name:   "Test Org",
			Status: pb.ItemStatus_Active,
		}
		capturePrint(org)

		value := &pb.OrgsResponse{
			Orgs: []*pb.Org{org},
		}
		capturePrint(value)
	})
}
