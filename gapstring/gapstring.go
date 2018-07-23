package gapstring

import (
	"fmt"
	"encoding/binary"
	"encoding/hex"
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


type GapString struct {
	chunks []chunk
}

func New() GapString {
	return GapString{
		chunks: []chunk{},
	}
}

func OfGap(gap int) GapString {
	return GapString{
		chunks: []chunk{{gap: gap}},
	}
}

func OfBytes(b []byte) GapString {
	return GapString{
		chunks: []chunk{{data: b}},
	}
}

func OfString(s string) GapString {
	return OfBytes([]byte(s))
}

func (g GapString) Length() int {
	n := 0
	for _, c := range g.chunks {
		n += c.length()
	}
	return n
}

func (g GapString) Missing() int {
	n := 0
	for _, c := range g.chunks {
		n += c.missing()
	}
	return n
}

func (g GapString) Append(h GapString) GapString {
	if h.Length() > 0 {
		return GapString{
			chunks: append(g.chunks, h.chunks...),
		}
	} else {
		return g
	}
}

func (g GapString) AppendGap(gap int) GapString {
	return g.Append(OfGap(gap))
}

func (g GapString) AppendBytes(b []byte) GapString {
	return g.Append(OfBytes(b))
}

func (g GapString) AppendString(s string) GapString {
	return g.Append(OfString(s))
}

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

// Returns -1 if it's a gap
func (g GapString) ValueAt(pos int) int {
	v := g.Slice(pos, pos+1)
	if v.chunks[0].gap > 0 {
		return -1
	} else {
		return int(v.chunks[0].data[0])
	}
}

func (g GapString) String(fill string) string {
	return string(g.Bytes([]byte(fill)...))
}

func (g GapString) HexString(fill ...byte) string {
	return hex.EncodeToString(g.Bytes(fill...))
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
func (g GapString) Hexdump() string {
	out := new(strings.Builder)
	skipping := false
	glen := g.Length()
	pos := 0
	for ; pos < glen; {
		// Check for repeats
		repeated := true
		if (pos > 0) {
			for i := 0; (i < 16) && (pos+i < glen); i += 1 {
				if g.ValueAt(pos+i) != g.ValueAt(pos+i-16) {
					repeated = false
					break
				}
			}
			if repeated {
				if ! skipping {
					fmt.Fprintln(out, "*")
					skipping = true
				}
				pos += 16
				continue
			} else {
				skipping = false
			}
		}

		// Output offset
		fmt.Fprintf(out, "%08x  ", pos)
		
		// Output octet values
		for i := 0; i < 16; i += 1 {
			if pos+i < glen {
				c := g.ValueAt(pos+i)
				if c == -1 {
					fmt.Fprintf(out, "-- ")
				} else {
					fmt.Fprintf(out, "%02x ", c)
				}
			} else {
				fmt.Fprintf(out, "   ")
			}
			if i == 7 {
				fmt.Fprintf(out, " ")
			}
		}
		
		fmt.Fprintf(out, " ")
		
		
		// Output octet glyphs
		for i := 0; (i < 16) && (pos < glen); {
			c := g.ValueAt(pos)
			if c == -1 {
				fmt.Fprintf(out, "�")
			} else {
				fmt.Fprintf(out, "%c", fluffych[c])
			}
			i += 1
			pos += 1
		}
		
		// Output newline
		fmt.Fprintln(out, "")
	}
	fmt.Fprintf(out, "%08x\n", pos)
	
	return out.String()
}

func (g GapString) Uint32LE() (uint32, GapString) {
	return binary.LittleEndian.Uint32(g.Slice(0, 4).Bytes()), g.Slice(4, g.Length())
}

func (g GapString) Uint16LE() (uint16, GapString) {
	return binary.LittleEndian.Uint16(g.Slice(0, 2).Bytes()), g.Slice(2, g.Length())
}

func (g GapString) Utf16(o binary.ByteOrder, fill string) string {
	in := g.Bytes([]byte(fill)...)
	ints := make([]uint16, len(in)/2)
	
	for i := 0; i < len(in); i += 2 {
		ints[i/2] = o.Uint16(in[i:])
	}
	return string(utf16.Decode(ints))
}

func (g GapString) Utf16LE(gap string) string {
	return g.Utf16(binary.LittleEndian, gap)
}

func (g GapString) Utf16BE(gap string) string {
	return g.Utf16(binary.BigEndian, gap)
}

