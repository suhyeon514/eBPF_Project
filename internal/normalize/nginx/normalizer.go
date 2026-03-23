package nginx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/suhyeon514/eBPF_Project/internal/model"
)

type Normalizer struct {
	host model.HostMeta
}

func New(host model.HostMeta) *Normalizer {
	return &Normalizer{host: host}
}

// 🔥 nginx access log 정규식 (기본형)
var logRegex = regexp.MustCompile(`^(\S+) - - \[(.*?)\] "(\S+) (.*?) (\S+)" (\d{3})`)

func (n *Normalizer) Normalize(_ context.Context, raw model.RawEnvelope) ([]model.Event, error) {

	// 🔥 Payload 추출 (핵심 수정)
	data, ok := raw.Payload.(model.RawJSON)
	if !ok {
		return nil, nil
	}

	line := strings.TrimSpace(string(data.Data))
	if line == "" {
		return nil, nil
	}

	// 🔥 로그 파싱
	matches := logRegex.FindStringSubmatch(line)
	if len(matches) < 6 {
		return nil, nil // 파싱 실패 시 드랍
	}

	ip := matches[1]
	method := matches[3]
	url := matches[4]
	status := matches[6]

	// 🔥 이벤트 생성
	ev := model.NewEvent(
		mustEventID(),
		// model.EventType("web.access"),
		model.EventWebAccess,
		time.Now().UTC(),
		n.host,
		model.CollectorMeta{
			Name:       "nginx",
			SourceType: "web",
		},
	)

	// 🔥 핵심 데이터 넣기 (Labels 활용)
	if ev.Labels == nil {
		ev.Labels = map[string]string{}
	}

	ev.Labels["ip"] = ip
	ev.Labels["method"] = method
	ev.Labels["url"] = url
	ev.Labels["status"] = status

	// 🔥 RawRef
	ev.RawRef = &model.RawReference{
		Source:  string(raw.Source),
		RawType: raw.RawType,
	}

	return []model.Event{ev}, nil
}

////////////////////////////////////////////////////////////
// 🔧 헬퍼 함수
////////////////////////////////////////////////////////////

func mustEventID() string {
	id, err := newEventID()
	if err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UTC().UnixNano())
	}
	return id
}

func newEventID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%s", time.Now().UTC().UnixNano(), hex.EncodeToString(b[:])), nil
}
