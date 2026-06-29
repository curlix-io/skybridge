package mask

import "context"

// Chain applies maskers in order (e.g. the remote masker, then the column overlay). The first
// error short-circuits. Nil maskers are skipped.
type Chain struct {
	maskers []Masker
}

// NewChain composes maskers left-to-right.
func NewChain(maskers ...Masker) *Chain {
	out := make([]Masker, 0, len(maskers))
	for _, m := range maskers {
		if m != nil {
			out = append(out, m)
		}
	}
	return &Chain{maskers: out}
}

// MaskRow implements Masker.
func (c *Chain) MaskRow(ctx context.Context, cols []Column, row [][]byte) ([][]byte, error) {
	var err error
	for _, m := range c.maskers {
		row, err = m.MaskRow(ctx, cols, row)
		if err != nil {
			return row, err
		}
	}
	return row, nil
}
