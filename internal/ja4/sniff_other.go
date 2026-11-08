//go:build !linux

package ja4

import (
	"context"
	"errors"
	"time"
)

// Sniff is only supported on Linux.
func Sniff(context.Context, []uint16, func(Result), func(Stats), time.Duration) error {
	return errors.New("ja4: packet capture is only supported on Linux")
}
