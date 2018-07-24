/*
package netshovel/gapstring provides a GapString type,
which represents a byte array with gaps: holes with no data.
This is used by netshovel to represent
captured data streams with drops.

Gaps are represented efficiently,
both in memory and in computation.
Several convenience functions exist
which operate on GapString data,
while preserving the gaps.
*/
package gapstring

import (
	"bytes"
	"fmt"
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// XXX: I think there's a clever way to do this with interfaces
// XXX: But I'm too exhausted to figure it out.
// XXX: I'll have to fix it later; it doesn't matter much for performance

type chunk struct {
	gap int // This takes precedence over data
	data []byte
}

func (c chunk) length() int {
	if c.gap > 0 {
		return c.gap
	} else {
		return len(c.data)
	}
}

func (c chunk) missing() int {
	return c.gap
}

func (c chunk) slice(a, b int) chunk {
	if b > c.length() {
		panic("runtime error: index out of range")
	}
	if c.gap > 0 {
		return chunk{gap: b - a}
	} else {
		return chunk{data: c.data[a:b]}
	}
}

// A GapString is a string with gaps of no data in the middle
type GapString struct {
	chunks []chunk
}

// Return a new zero-length GapString
func New() GapString {
	return GapString{
		chunks: []chunk{},
	}
}

// Return a new GapString containing a gap
func OfGap(gap int) GapString {
	return GapString{
		chunks: []chunk{{gap: gap}},
	}
}

// Return a new GapString containing some bytes
func OfBytes(b []byte) GapString {
	return GapString{
		chunks: []chunk{{data: b}},
	}
}

// Return a new GapString containing a string
func OfString(s string) GapString {
	return OfBytes([]byte(s))
}

// Return the length of a GapString
//
// This is the number of bytes you would have if the gaps were filled with some value.
func (g GapString) Length() int {
	n := 0
	for _, c := range g.chunks {
		n += c.length()
	}
	return n
}

// Return the total size of all gaps
func (g GapString) Missing() int {
	n := 0
	for _, c := range g.chunks {
		n += c.missing()
	}
	return n
}

// Return the current GapString with another GapString appended
func (g GapString) Append(h GapString) GapString {
	if h.Length() > 0 {
		return GapString{
			chunks: append(g.chunks, h.chunks...),
		}
	} else {
		return g
	}
}

// Return the current GapString with a gap appended
func (g GapString) AppendGap(gap int) GapString {
	return g.Append(OfGap(gap))
}

// Return the current GapString with some bytes appended
func (g GapString) AppendBytes(b []byte) GapString {
	return g.Append(OfBytes(b))
}

// Return the current GapString with a string appended
func (g GapString) AppendString(s string) GapString {
	return g.Append(OfString(s))
}

// Return a slice of this GapString
//
// This is what you would expect from g[start:end],
// if g were a string or byte slice.
func (g GapString) Slice(start, end int) GapString {
	outchunks := make([]chunk, 0, len(g.chunks))
	
	if end > g.Length() {
		panic("runtime error: slice bounds out of range")
	}
	
	for _, c := range g.chunks {
		chunklen := c.length()

		// Discard chunks that appear before the first
		if start > chunklen {
			start -= chunklen
			end -= chunklen
			continue
		}

		// Append chunks until we're done
		cend := chunklen
		if cend > end {
			cend = end
		}
		if start != cend {
			outchunks = append(outchunks, c.slice(start, cend))
		}
		start = 0
		end -= cend
		
		if end == 0 {
			break
		}
	}
	
	return GapString{chunks: outchunks}
}

// Return this GapString with the provided xor mask applied
//
// The mask is cycled for the length of the GapString.
func (g GapString) Xor(mask ...byte) GapString {
	ret := GapString{}
	pos := 0
	for _, c := range g.chunks {
		ret = ret.AppendGap(c.gap)
		
		out := make([]byte, len(c.data))
		for i, b := range c.data {
			m := mask[(pos+i)%len(mask)]
			out[i] = b ^ m
		}
		ret = ret.AppendBytes(out)

		pos += c.length()
	}
	return ret
}

// Return this GapString with gaps filled in
func (g GapString) Bytes(fill ...byte) []byte {
	ret := make([]byte, g.Length())
	pos := 0
	for _, c := range g.chunks {
		// Fill in gap
		if len(fill) > 0 {
			for i := 0; i < c.gap; i += 1 {
				ret[pos] = fill[pos % len(fill)]
				pos += 1
			}
		}
		// Fill in bytes
		for _, b := range c.data {
			ret[pos] = b
			pos += 1
		}
	}
	ret = ret[0:pos]
	return ret
}

// Returns the value at a specific position
//
// This returns the byte if one is present, or -1 if it's a gap
func (g GapString) ValueAt(pos int) int {
	v := g.Slice(pos, pos+1)
	if v.chunks[0].gap > 0 {
		return -1
	} else {
		return int(v.chunks[0].data[0])
	}
}

// Return a string version of the GapString, with gaps filled in
func (g GapString) String(fill string) string {
	return string(g.Bytes([]byte(fill)...))
}

// Return a hex representation of this GapString
//
// Each octet is space-separated, and gaps are represented with "--"
func (g GapString) HexString() string {
	out := new(strings.Builder)
	glen := g.Length()
	for i := 0; i < glen; i += 1 {
		c := g.ValueAt(i)
		if c == -1 {
			out.WriteString("--")
		} else {
			// There's probably a faster way to do this. Do we care?
			fmt.Fprintf(out, "%02x", c)
		}
		if i + 1 < glen {
			out.WriteRune(' ')
			if i % 8 == 7 {
				out.WriteRune(' ')
			}
		}
	}
	return out.String()
}

var fluffych = []rune{
  '·', '☺', '☻', '♥', '♦', '♣', '♠', '•', '◘', '○', '◙', '♂', '♀', '♪', '♫', '☼',
	'►', '◄', '↕', '‼', '¶', '§', '▬', '↨', '↑', '↓', '→', '←', '∟', '↔', '▲', '▼',
	' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?',
	'@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
	'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_',
	'`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
	'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', '⌂',
	'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å',
	'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ',
	'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»',
	'░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐',
	'└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧',
	'╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐', '▀',
	'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩',
	'≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∀', '∃', '√', 'ⁿ', '²', '■', '¤',
}

// Return a rune representation of this GapString
//
// This uses the glyph set from the Fluffy toolkit
// (https://dirtbags.github.io/fluffy/).
// Gaps are represented with the rune '�'
func (g GapString) Runes() string {
	out := new(strings.Builder)
	glen := g.Length()
	for i := 0; i < glen; i += 1 {
		c := g.ValueAt(i)
		if c == -1 {
			out.WriteRune('�')
		} else {
			out.WriteRune(fluffych[c])
		}
	}
	return out.String()
}

// Return a hex dump of this GapString
func (g GapString) Hexdump() string {
	out := new(strings.Builder)
	skipping := false
	glen := g.Length()
	pos := 0
	prev := []byte{}
	for ; pos < glen; {
		// Check for repeats
		end := pos + 16
		if end > glen {
			end = glen
		}
		cur := g.Slice(pos, end)
		curBytes := cur.Bytes()
		if 0 == bytes.Compare(prev, curBytes) {
			if ! skipping {
				fmt.Fprintln(out, "*")
				skipping = true
			}
			continue
		}

		fmt.Fprintf(out, "%08x  ", pos)
		fmt.Fprintf(out, "%-50s", cur.HexString())
		fmt.Fprintln(out, cur.Runes())

		pos += cur.Length()
	}
	fmt.Fprintf(out, "%08x\n", pos)
	
	return out.String()
}

// Return a uint32, little-endian, taken from the front of this GapString
//
// The rest of the GapString is returned as the second argument.
func (g GapString) Uint32LE() (uint32, GapString) {
	return binary.LittleEndian.Uint32(g.Slice(0, 4).Bytes(0)), g.Slice(4, g.Length())
}

// Return a uint16, little-endian, taken from the front of this GapString
//
// The rest of the GapString is returned as the second argument.
func (g GapString) Uint16LE() (uint16, GapString) {
	return binary.LittleEndian.Uint16(g.Slice(0, 2).Bytes(0)), g.Slice(2, g.Length())
}

// Return this GapString decoded as UTF-16
func (g GapString) Utf16(order binary.ByteOrder, fill string) string {
	in := g.Bytes([]byte(fill)...)
	ints := make([]uint16, len(in)/2)
	
	for i := 0; i < len(in); i += 2 {
		ints[i/2] = order.Uint16(in[i:])
	}
	return string(utf16.Decode(ints))
}

// Return this GapString decoded as UTF-16 Little Endian
//
// This format is used extensively in Microsoft Windows.
func (g GapString) Utf16LE(gap string) string {
	return g.Utf16(binary.LittleEndian, gap)
}

// Return this GapString decoded as UTF-16 Big Endian
func (g GapString) Utf16BE(gap string) string {
	return g.Utf16(binary.BigEndian, gap)
}

