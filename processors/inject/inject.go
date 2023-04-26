package processor

import (
	"github.com/superfly/tokenizer"
)

func init() {
	tokenizer.RegisterProcessor("inject", tokenizer.Inject)
}
