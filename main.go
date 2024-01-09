package main

import (
	"fmt"
  "encoding/hex"
  "net"
  "strings"
  "time"
)

var (
  UUIDTimeBase = time.Date(1582, 10, 15, 0, 0, 0, 0, time.UTC)
  SELTimeBase = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
)
const (
  UUITTimeUnit = 100 * time.Nanosecond
  MaxDurationUnit = (1<<63 - 1) / 100 // maximum time.Duration in 100-ns units
)

func WrapTraceableErrorf(err error, format string, args ...any) error {
  msg := fmt.Sprintf(format, args...)
  if err != nil {
    return fmt.Errorf("%s: %w", msg, err)
  }
  return fmt.Errorf("%s", msg)
}

// UUIDVariant is the UUID variant
type UUIDVariant int

// UUIDVariant enum
const (
	NullVariant      UUIDVariant = iota // for null UUID only
	VariantNCS                          // 0..7
	VariantRFC4122                      // 8..B
	VariantMicrosoft                    // C..D
	VariantFuture                       // E..F
)

func (u UUIDVariant) String() string {
	switch u {
	case VariantNCS:
		return "Variant-0 (NCS)" // obsoltete
	case VariantRFC4122:
		return "Variant-1 (RFC4122)"
	case VariantMicrosoft:
		return "Variant-2 (Microsoft)" // legacy, obsoltete
	default:
		return "FutureVariants"
	}
}

// MACAddrBytes represents the MAC Address in []byte
type MACAddrBytes net.HardwareAddr

// ToString returns MAC Address string with delimiter
func (m MACAddrBytes) ToString(delimiter string, useUpper bool) string {
	if m == nil {
		return "<Null_MAC_Address>"
	}
	s := net.HardwareAddr(m).String()
	if useUpper {
		s = strings.ToUpper(s)
	}
  if delimiter != ":" {
		s = strings.ReplaceAll(s, ":", delimiter)
	}
	return s
}

func (m MACAddrBytes) String() string {
	return m.ToString(":", false)
}

// Parse parses the MAC address string and set it to the object
func (m *MACAddrBytes) Parse(s string) error {
	ha, err := net.ParseMAC(s)
	if err != nil {
		return WrapTraceableErrorf(err, "failed to parse MAC address")
	}
	*m = MACAddrBytes(ha)
	return nil
}

// UUIDVersion is the UUID version
type UUIDVersion int

func (v UUIDVersion) String() string {
	if v < 0 {
		return fmt.Sprintf("<Invalid_Version:%d>", v)
	} else if v == 0 {
		return "Version-Null_UUID"
	}
	return fmt.Sprintf("Version-%d", v)
}

// UUIDByte is the UUID data ib []byte
type UUIDByte []byte

const (
	secondFieldIdx = 4
	versionIdx     = 6
	variantIdx     = 8
	macIdx         = 10
	uuidLength     = 16
	macLength      = 6
)

func (u UUIDByte) String() string {
	var b strings.Builder
	lastIdx := 0
	for i, l := range []int{secondFieldIdx, versionIdx, variantIdx, macIdx, uuidLength} {
		if i > 0 {
			b.WriteString("-")
		}
		b.WriteString(hex.EncodeToString(u[lastIdx:l]))
		lastIdx = l
	}
	return strings.ToUpper(b.String())
}

func (u UUIDByte) Version() UUIDVersion {
	return UUIDVersion(u[versionIdx] >> 4)
}

func (u UUIDByte) Variant() UUIDVariant {
	v := u[variantIdx] >> 4
	switch {
	case v <= 7:
		return VariantNCS
	case v >= 8 && v <= 0x0b:
		return VariantRFC4122
	case v >= 0x0c && v <= 0x0d:
		return VariantMicrosoft
	default:
		return VariantFuture
	}
}

// for version 1 and 2 only
func (u UUIDByte) MacAddr() MACAddrBytes {
	if u.Version() <= 2 {
		theMAC := make(MACAddrBytes, macLength)
		copy(theMAC, u[macIdx:])
    return theMAC
	}
  return nil
}

// for version 1 and 2 only
func (u UUIDByte) TimeInfo(le bool) (theTime time.Time, clkSeq, domain, localID int) {
  version := u.Version()
  var timeLow uint32
  i := 0
  for m := uint32(1); i < secondFieldIdx; i++ { // time low
    v := uint32(u[i])
    if le {
      timeLow += v * m
      m <<= 8
    } else {
      timeLow = (timeLow << 8) + v
    }
  }
  var timeMid uint16
  i = secondFieldIdx
  if le {
    timeMid = uint16(u[i]) + uint16(u[i+1]) << 8
  } else {
    timeMid = (uint16(u[i]) << 8) + uint16(u[i+1])
  }
  var timeHigh uint16
  i = versionIdx
  if le {
    timeHigh = uint16(u[i] & 0x0f) + uint16(u[i+1]) << 4
  } else {
    timeHigh = (uint16(u[i] & 0x0f) << 8) + uint16(u[i+1])
  }
  var timeUnits int64
  switch version {
  case 1:
    timeUnits = int64(timeLow) + int64(timeMid) << 32 + int64(timeHigh) << 48 // a 60-bit number of 100-nansecond unit
  case 2:
    timeUnits = int64(timeMid) << 32 + int64(timeHigh) << 48 // a 60-bit number of 100-nansecond unit
    localID = int(timeLow)
  }
  // when converting this to nanoseconds, it will overflow int64
  // break it down
  theTime = UUIDTimeBase
  for timeUnits > 0 {
    if timeUnits > MaxDurationUnit {
      theTime = theTime.Add(MaxDurationUnit*UUITTimeUnit)
      timeUnits -= MaxDurationUnit
    } else {
      theTime = theTime.Add(time.Duration(timeUnits)*UUITTimeUnit)
      timeUnits = 0
    }
  }
  
  clkSeq = int(u.MaskVariant()) 
  switch version {
  case 1:
    clkSeq = (clkSeq << 8) + int(u[variantIdx+1])
  case 2:
    domain = int(u[variantIdx+1])
  }
  return
}

func (u UUIDByte) MaskVariant() byte {
  b := u[variantIdx]
  switch {
  case b & 0x80 == 0:
    b &= 0x7f // msb is variant
  case b & 0xc0 == 0x80:
    b &= 0x3f // higher 2 bits are variant
  default: // higher 3 bits are variant
    b &= 0x1f
  }
  return b
}

// for version 3, 4, and 5
func (u UUIDByte) DataInfo() []byte {
  b := make([]byte, len(u))
  copy(b, u)
  b[versionIdx] &= 0x0f
  b[variantIdx] = u.MaskVariant()
  return b
}

func (u UUIDByte) Info() string {
  var b strings.Builder
  fmt.Fprintf(&b, "UUID: %s\n", u.String())
  fmt.Fprintf(&b, " * Variant: %s\n", u.Variant())
  version := u.Version()
  fmt.Fprintf(&b, " * Version: %s\n", version)
  switch version {
  case 1, 2:
    fmt.Fprintf(&b, " * MAC Address: %s\n", u.MacAddr())
    ts, clk, domain, localID := u.TimeInfo(false)
    fmt.Fprintf(&b, " * Timestamp: %s\n", ts)
    if version == 1 {
      fmt.Fprintf(&b, " * Clock Sequence: %d\n", clk)
    } else {
      fmt.Fprintf(&b, " * Local ID: %d\n", localID)
      fmt.Fprintf(&b, " * Domain: %d\n", domain)
      fmt.Fprintf(&b, " * Clock Sequence: %d\n", clk)
    }
  case 3, 4, 5:
    data := u.DataInfo()
    name := "Hash"
    if version == 4 {
      name = "Random"
    }
    s := make([]string, len(data))
    for i, d := range data {
      s[i] = fmt.Sprintf("%02x", d)
    }
    fmt.Fprintf(&b, " * %s Data (%d): %s\n", name, len(data), strings.Join(s, ":"))
    
  }
  return b.String()
}

func (u *UUIDByte) FromString(src string) error {
	s := strings.Replace(src, "-", "", -1)
	if s[0] == '{' {
		s = strings.TrimPrefix(s, "{")
		s = strings.TrimSuffix(s, "}")
	} else {
		s = strings.TrimPrefix(s, "urn:uuid:")
	}

	*u = make(UUIDByte, hex.DecodedLen(len(s)))
	if n, err := hex.Decode(*u, []byte(s)); err != nil {
		return WrapTraceableErrorf(err, "unable to decode UUID string %q", src)
	} else if n != uuidLength {
		return WrapTraceableErrorf(nil,
			"failed to decode UUID string %q: wrong length of bytes (%d), expected %d", src, n, uuidLength)
	}
	return nil
}

func main() {
  var u UUIDByte
  u.FromString("8be4df61-93ca-11d2-aa0d-00e098032b8c")
	fmt.Printf("UUID: %s\n", u)
  fmt.Printf("Info:\n%s\n", u.Info())

  u.FromString("8be4df61-93ca-21d2-aa0d-00e098032b8c")
	fmt.Printf("UUID: %s\n", u)
  fmt.Printf("Info:\n%s\n", u.Info())

  u.FromString("8be4df61-93ca-31d2-aa0d-00e098032b8c")
	fmt.Printf("UUID: %s\n", u)
  fmt.Printf("Info:\n%s\n", u.Info())

  u.FromString("8be4df61-93ca-41d2-aa0d-00e098032b8c")
	fmt.Printf("UUID: %s\n", u)
  fmt.Printf("Info:\n%s\n", u.Info())

  u.FromString("8be4df61-93ca-51d2-aa0d-00e098032b8c")
	fmt.Printf("UUID: %s\n", u)
  fmt.Printf("Info:\n%s\n", u.Info())

  // cab00d1e-cab0-10d1-beca-00decab00d1e
  u.FromString("cab00d1e-cab0-10d1-beca-00decab00d1e")
  fmt.Printf("UUID: %s\n", u)
  fmt.Printf("Info:\n%s\n", u.Info())

  d := time.Now().UTC().Sub(SELTimeBase)
  fmt.Printf("Since: %#x, %#x\n", int64(d), int64(d >> 16))
  fmt.Printf("%s\n", d - (d>>16)<<16)
  fmt.Printf("Since: %#x, %#x\n", uint32(d/time.Second), uint16((d-(d / time.Second) * time.Second)>>16))
}
