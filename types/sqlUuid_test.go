package types_test

import (
	"fmt"
	"testing"

	"github.com/bitsbuster/utils/types"
)

func TestNew(t *testing.T) {
	kk := types.SqlUuid{}
	kk.New()

	fmt.Printf("kk: %v\n", kk)
}
