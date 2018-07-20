package gapstring

import (
	"bytes"
	"testing"
)

func assertEqual(name string, a, b interface{}, t *testing.T) {
	if a != b {
		t.Errorf("%s: %#v != %#v", name, a, b)
	}
}

func TestChunk(t *testing.T) {
	var c chunk
	
	c = chunk{gap: 2}
	assertEqual("gap chunk", c.length(), 2, t)
	
	c = chunk{data: []byte("moo")}
	assertEqual("byte chunk", c.length(), 3, t)
	assertEqual("byte slice", string(c.slice(1,3).data), "oo", t)
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
	if g.String("") != "moobarbaz" {
		t.Errorf("String conversion with empty string")
	}
	if g.String("DROP") != "moobarOPDROPDRbaz" {
		t.Errorf("String conversion with fill")
	}
	
	assertEqual("slice", g.Slice(2, 5).String(""), "oba", t)

	hexdump :=
		"00000000  6d 6f 6f 62 61 72 -- --  -- -- -- -- -- -- 62 61  moobar��������ba\n" +
		"00000010  7a                                                z\n" +
		"00000011\n"
	assertEqual("hexdump", g.Hexdump(), hexdump, t)
}
