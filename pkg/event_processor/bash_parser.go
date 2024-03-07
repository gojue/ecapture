package event_processor

import (
	"context"
	"ecapture/user/config"
	"errors"

	"golang.org/x/sys/unix"
)

type BashParser struct {
	line   string
	isdone bool
}

func (b *BashParser) Display() []byte {
	return []byte("Line: " + b.line)
}

func (b *BashParser) Init() {
	b.isdone = false
	b.line = ""
}

func (b *BashParser) IsDone() bool {
	return b.isdone
}

func (b *BashParser) Name() string {
	return "BashParser"
}

func (b *BashParser) PacketType() PacketType {
	return PacketTypeBash
}

func (b *BashParser) ParserType() ParserType {
	return ParserTypeBash
}

func (b *BashParser) Reset() {
	b.isdone = false
	b.line = ""
}

func (bp *BashParser) Write(b []byte) (int, error) {
	bp.line += unix.ByteSliceToString((b[:]))
	return len(bp.line), nil
}

func (bp *BashParser) detect(ctx context.Context, b []byte) error {
	if ctx.Value(config.CONTEXT_KEY_MODULE_NAME) == "EBPFProbeBash" {
		return nil
	}
	return errors.New("event is not about bash")
}

func init() {
	be := &BashParser{}
	be.Init()
	Register(be)
}
