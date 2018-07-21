package gapstring

import (
	"bytes"
	"testing"
)

func assertEqual(t *testing.T, name string, a, b interface{}) {
	if a != b {
		t.Errorf("%s: %#v != %#v", name, a, b)
	}
}

func TestChunk(t *testing.T) {
	var c chunk
	
	c = chunk{gap: 2}
	assertEqual(t, "gap chunk", c.length(), 2)
	
	c = chunk{data: []byte("moo")}
	assertEqual(t, "byte chunk", c.length(), 3)
	assertEqual(t, "byte slice", string(c.slice(1,3).data), "oo")
}

func TestGapString(t *testing.T) {
	g := GapString{}

	if 0 != bytes.Compare(g.Bytes(), []byte{}) {
		t.Errorf("%#v.Bytes() != []byte{}", g)
	}
	if g.Length() != 0 {
		t.Errorf("len(%#v) != 0", g)
	}

	g = g.Append(g)
	if g.Length() != 0 {
		t.Errorf("Appending two emtpy gapstrings")
	}
	
	g = g.AppendString("moo")
	if 0 != bytes.Compare(g.Bytes(), []byte("moo")) {
		t.Errorf("Simple string")
	}
	
	g = g.AppendString("bar")
	if g.String("") != "moobar" {
		t.Errorf("Append")
	}
	if g.Missing() != 0 {
		t.Errorf("Missing when there shouldn't be any missing")
	}
	
	g = g.AppendGap(8)
	if g.Length() != 3+3+8 {
		t.Errorf("Length after gap append")
	}
	if g.Missing() != 8 {
		t.Errorf("Gap miscounted")
	}
	
	g = g.AppendString("baz")
	assertEqual(t, "string", g.String(""), "moobarbaz")
	assertEqual(t, "string drop", g.String("DROP"), "moobarOPDROPDRbaz")

	assertEqual(t, "xor", g.Xor(1).String(""), "lnnc`sc`{")
	assertEqual(t, "xor drop", g.Xor(1).String("DROP"), "lnnc`sOPDROPDRc`{")
	
	assertEqual(t, "slice", g.Slice(2, 5).String(""), "oba")
	assertEqual(t, "slice+xor", g.Slice(2, 5).Xor(1).String(""), "nc`")

	hexdump :=
		"00000000  6d 6f 6f 62 61 72 -- --  -- -- -- -- -- -- 62 61  moobar��������ba\n" +
		"00000010  7a                                                z\n" +
		"00000011\n"
	assertEqual(t, "hexdump", g.Hexdump(), hexdump)
}
