// Code generated by "stringer -type=BlockMode"; DO NOT EDIT.

package cryptopals

import "strconv"

const _BlockMode_name = "UnknownBlockModeECBBlockModeCBCBlockMode"

var _BlockMode_index = [...]uint8{0, 16, 28, 40}

func (i BlockMode) String() string {
	if i < 0 || i >= BlockMode(len(_BlockMode_index)-1) {
		return "BlockMode(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _BlockMode_name[_BlockMode_index[i]:_BlockMode_index[i+1]]
}
