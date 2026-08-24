package fuzzer

import "fmt"

type AttackType string

const (
	Sniper       AttackType = "sniper"
	BatteringRam AttackType = "battering-ram"
	Pitchfork    AttackType = "pitchfork"
	ClusterBomb  AttackType = "cluster-bomb"
)

func ValidAttackType(t string) bool {
	switch AttackType(t) {
	case Sniper, BatteringRam, Pitchfork, ClusterBomb:
		return true
	}
	return false
}

func ParseAttackType(t string) (AttackType, error) {
	if !ValidAttackType(t) {
		return "", fmt.Errorf("invalid attack type %q — use sniper|battering-ram|pitchfork|cluster-bomb", t)
	}
	return AttackType(t), nil
}

func ComboCount(positions []*Position, sets [][]string, attack AttackType) (int, error) {
	combos, err := Combos(positions, sets, attack)
	if err != nil {
		return 0, err
	}
	return len(combos), nil
}

func Combos(positions []*Position, sets [][]string, attack AttackType) ([][]string, error) {
	if len(positions) == 0 {
		return nil, fmt.Errorf("no positions configured — add one with: fuzz position add")
	}
	switch attack {
	case Sniper:
		if len(sets) == 0 {
			return nil, fmt.Errorf("no payload set configured — add one with: fuzz payload")
		}
		var out [][]string
		for posIdx := range positions {
			for _, p := range sets[0] {
				vec := make([]string, len(positions))
				vec[posIdx] = p
				out = append(out, vec)
			}
		}
		return out, nil

	case BatteringRam:
		if len(sets) == 0 {
			return nil, fmt.Errorf("no payload set configured — add one with: fuzz payload")
		}
		var out [][]string
		for _, p := range sets[0] {
			vec := make([]string, len(positions))
			for i := range vec {
				vec[i] = p
			}
			out = append(out, vec)
		}
		return out, nil

	case Pitchfork:
		if len(sets) != len(positions) {
			return nil, fmt.Errorf("pitchfork needs one payload set per position (%d positions, %d sets)", len(positions), len(sets))
		}
		min := len(sets[0])
		for _, s := range sets[1:] {
			if len(s) < min {
				min = len(s)
			}
		}
		if min == 0 {
			return nil, fmt.Errorf("pitchfork: empty payload set")
		}
		var out [][]string
		for k := 0; k < min; k++ {
			vec := make([]string, len(positions))
			for i := range positions {
				vec[i] = sets[i][k]
			}
			out = append(out, vec)
		}
		return out, nil

	case ClusterBomb:
		if len(sets) != len(positions) {
			return nil, fmt.Errorf("cluster-bomb needs one payload set per position (%d positions, %d sets)", len(positions), len(sets))
		}
		var out [][]string
		total := 1
		for _, s := range sets {
			total *= len(s)
		}
		for k := 0; k < total; k++ {
			idx := k
			vec := make([]string, len(positions))
			for i := range positions {
				vec[i] = sets[i][idx%len(sets[i])]
				idx /= len(sets[i])
			}
			out = append(out, vec)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown attack type %q", attack)
}
