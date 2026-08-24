package report

import "encoding/json"

func (r *Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
