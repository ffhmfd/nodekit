package platform

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Firewall struct{ Run Runner }

func (f Firewall) backend(ctx context.Context) (string, error) {
	if f.Run == nil {
		f.Run = Exec
	}
	b, e := f.Run(ctx, "ufw", "status")
	if e == nil && strings.Contains(string(b), "Status: active") {
		return "ufw", nil
	}
	if _, e = f.Run(ctx, "iptables", "-S", "INPUT"); e == nil {
		return "iptables", nil
	}
	return "", errors.New("unsupported firewall layout; select manual mode and allow only project ports")
}

func validateBindings(groups ...[]Binding) error {
	for _, bindings := range groups {
		for _, b := range bindings {
			if err := b.validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

// Apply is ensure-only: startup may have no durable transaction or rollback
// snapshot. Reuse covering legacy ownership, add missing allowances safely,
// and never delete existing rules. Family/format migration belongs to Reconcile.
func (f Firewall) Apply(ctx context.Context, bindings []Binding) error {
	if err := validateBindings(bindings); err != nil {
		return err
	}
	if len(bindings) == 0 {
		return nil
	}
	if f.Run == nil {
		f.Run = Exec
	}
	backend, err := f.backend(ctx)
	if err != nil {
		return err
	}
	if backend == "ufw" {
		return f.reconcileUFW(ctx, nil, bindings, false, false, true)
	}
	return f.reconcileTables(ctx, nil, bindings, false, true)
}

// Reconcile compares backend physical identities, never raw struct difference.
// Callers must durably journal old and next before calling it. On any error the
// operation may be partial; Restore union(old,next) back to a saved Snapshot
// to compensate, retaining the journal if compensation cannot be verified.
func (f Firewall) Reconcile(ctx context.Context, old, next []Binding) error {
	if err := validateBindings(old, next); err != nil {
		return err
	}
	if len(old)+len(next) == 0 {
		return nil
	}
	if f.Run == nil {
		f.Run = Exec
	}
	backend, err := f.backend(ctx)
	if err != nil {
		return err
	}
	if backend == "ufw" {
		return f.reconcileUFW(ctx, old, next, false, false, false)
	}
	return f.reconcileTables(ctx, old, next, false, false)
}

// Restore compensates a transition using Snapshot's physical provenance. It
// may recreate a previously owned generic UFW definition; ordinary Apply and
// Reconcile always create family-qualified rules when no generic remains.
func (f Firewall) Restore(ctx context.Context, known, snapshot []Binding) error {
	if err := validateBindings(known, snapshot); err != nil {
		return err
	}
	if len(known)+len(snapshot) == 0 {
		return nil
	}
	if f.Run == nil {
		f.Run = Exec
	}
	backend, err := f.backend(ctx)
	if err != nil {
		return err
	}
	if backend == "ufw" {
		return f.reconcileUFW(ctx, known, snapshot, false, true, false)
	}
	return f.reconcileTables(ctx, known, snapshot, false, false)
}

func (f Firewall) Remove(ctx context.Context, bindings []Binding) error {
	if err := validateBindings(bindings); err != nil {
		return err
	}
	if len(bindings) == 0 {
		return nil
	}
	if f.Run == nil {
		f.Run = Exec
	}
	backend, err := f.backend(ctx)
	if err != nil {
		return err
	}
	if backend == "ufw" {
		return f.reconcileUFW(ctx, bindings, nil, true, false, false)
	}
	return f.reconcileTables(ctx, bindings, nil, true, false)
}

// Snapshot retains raw ownership records plus observed UFW restoration
// families. A legacy IPv6 flag is intent, not proof of actual coverage: a
// generic rule may own both families or only one. Call before staging changes,
// never use a mixed Old/New inventory as evidence of pre-transaction ownership.
func (f Firewall) Snapshot(ctx context.Context, bindings []Binding) ([]Binding, error) {
	if err := validateBindings(bindings); err != nil {
		return nil, err
	}
	out := append([]Binding(nil), bindings...)
	if len(bindings) == 0 {
		return out, nil
	}
	if f.Run == nil {
		f.Run = Exec
	}
	backend, err := f.backend(ctx)
	if err != nil {
		return nil, err
	}
	if backend != "ufw" {
		return out, nil
	}
	rules, status, err := f.ufwState(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[Binding]bool{}
	for _, b := range out {
		seen[b] = true
	}
	for _, b := range bindings {
		if b.Family != "" {
			continue
		}
		r := ufwRule{b.Network, b.Port, "any", legacyTag(b)}
		legacy4 := r
		legacy4.to = "0.0.0.0/0"
		legacy6 := r
		legacy6.to = "::/0"
		legacyOwned := rules[r] || rules[legacy4] || rules[legacy6]
		v4, v6 := legacyOwned && ufwPhysical(status, r, "ipv4"), legacyOwned && ufwPhysical(status, r, "ipv6")
		if v4 && v6 {
			if !b.IPv6 {
				b.IPv6 = true
				if !seen[b] {
					out = append(out, b)
					seen[b] = true
				}
			}
			continue
		}
		// Record one-family observations even when the raw intent says dual.
		// Explicit snapshot markers override that intent during compensation;
		// otherwise a v4-only generic rule could become dual on recreation.
		var physical []Binding
		for _, family := range []string{"ipv4", "ipv6"} {
			v := Binding{Network: b.Network, Port: b.Port, Family: family}
			to := "0.0.0.0/0"
			if family == "ipv6" {
				to = "::/0"
			}
			qualified := ufwRule{b.Network, b.Port, to, familyTag(v)}
			if family == "ipv4" && v4 || family == "ipv6" && v6 || rules[qualified] && ufwPhysical(status, qualified, family) {
				physical = append(physical, v)
			}
		}
		// Without an observed old rule we cannot claim any restoration family.
		// Fail before mutation instead of broadening on an eventual abort. A
		// normal Apply may repair missing intent without pretending it existed.
		if len(physical) == 0 {
			return nil, fmt.Errorf("cannot snapshot unobserved UFW ownership for %s/%d; apply/repair the current firewall first", b.Network, b.Port)
		}
		for _, v := range physical {
			if !seen[v] {
				out = append(out, v)
				seen[v] = true
			}
		}
	}
	return out, nil
}

func legacyTag(b Binding) string { return fmt.Sprintf("nodekit:%s:%d", b.Network, b.Port) }
func familyTag(b Binding) string { return fmt.Sprintf("nodekit:%s:%s:%d", b.Family, b.Network, b.Port) }

type tableRule struct {
	tool, network string
	port          int
	tag           string
}

func (r tableRule) args() []string {
	return []string{"-p", r.network, "--dport", fmt.Sprint(r.port), "-m", "comment", "--comment", r.tag, "-j", "ACCEPT"}
}
func tableCandidates(bindings []Binding) []tableRule {
	var out []tableRule
	seen := map[tableRule]bool{}
	for _, b := range expandBindings(bindings) {
		tool := "iptables"
		if b.Family == "ipv6" {
			tool = "ip6tables"
		}
		for _, tag := range []string{legacyTag(b), familyTag(b)} {
			r := tableRule{tool, b.Network, b.Port, tag}
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	return out
}

func (f Firewall) tablePresent(ctx context.Context, r tableRule) (bool, error) {
	_, err := f.Run(ctx, append([]string{r.tool, "-C", "INPUT"}, r.args()...)...)
	if err == nil {
		return true, nil
	}
	// iptables documents exit 1 for an absent check rule; syntax, permission,
	// lock, executable and cancellation failures are NOT proof of absence.
	var status interface{ ExitCode() int }
	if errors.As(err, &status) && status.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("cannot inspect exact %s project rule: %w", r.tool, err)
}

func (f Firewall) reconcileTables(ctx context.Context, old, next []Binding, remove, ensureOnly bool) error {
	candidates := tableCandidates(append(append([]Binding(nil), old...), next...))
	present := map[tableRule]bool{}
	for _, r := range candidates {
		found, err := f.tablePresent(ctx, r)
		if err != nil {
			return err
		}
		present[r] = found
	}
	desired := map[tableRule]bool{}
	for _, b := range expandBindings(next) {
		tool := "iptables"
		if b.Family == "ipv6" {
			tool = "ip6tables"
		}
		r := tableRule{tool, b.Network, b.Port, familyTag(b)}
		legacy := tableRule{tool, b.Network, b.Port, legacyTag(b)}
		// Reuse an exact old project comment on this executable only. Never
		// infer an iptables rule from its ip6tables counterpart.
		if present[legacy] {
			r = legacy
		} else {
			for _, raw := range next {
				if raw.Family == "" && raw.Network == b.Network && raw.Port == b.Port {
					r = legacy
					break
				}
			}
		}
		if desired[r] {
			continue
		}
		desired[r] = true
		if !present[r] {
			if _, err := f.Run(ctx, append([]string{r.tool, "-I", "INPUT", "1"}, r.args()...)...); err != nil {
				return err
			}
			found, err := f.tablePresent(ctx, r)
			if err != nil {
				return err
			}
			if !found {
				return errors.New("iptables project insertion could not be verified")
			}
		}
	}
	for _, r := range candidates {
		if !ensureOnly && present[r] && (remove || !desired[r]) {
			if _, err := f.Run(ctx, append([]string{r.tool, "-D", "INPUT"}, r.args()...)...); err != nil {
				return err
			}
			found, err := f.tablePresent(ctx, r)
			if err != nil {
				return err
			}
			if found {
				return errors.New("iptables project deletion could not be verified")
			}
		}
	}
	return nil
}

type ufwRule struct {
	network string
	port    int
	to, tag string
}

func (r ufwRule) args(remove bool) []string {
	args := []string{"ufw"}
	if remove {
		args = append(args, "--force", "delete")
	}
	return append(args, "allow", "proto", r.network, "from", "any", "to", r.to, "port", fmt.Sprint(r.port), "comment", r.tag)
}
func ufwDefinitions(bindings []Binding) map[ufwRule]bool {
	out := map[ufwRule]bool{}
	for _, b := range bindings {
		if b.Family == "" {
			out[ufwRule{b.Network, b.Port, "any", legacyTag(b)}] = true
			// A legacy generic definition can own either or both actual halves.
			out[ufwRule{b.Network, b.Port, "0.0.0.0/0", legacyTag(b)}] = true
			out[ufwRule{b.Network, b.Port, "::/0", legacyTag(b)}] = true
		}
		for _, v := range expandBindings([]Binding{b}) {
			to := "0.0.0.0/0"
			if v.Family == "ipv6" {
				to = "::/0"
			}
			out[ufwRule{v.Network, v.Port, to, familyTag(v)}] = true
		}
	}
	return out
}
func ufwDesired(bindings []Binding, present map[ufwRule]bool, restore, ensureOnly bool) map[ufwRule]map[string]bool {
	out := map[ufwRule]map[string]bool{}
	legacy := map[string]bool{}
	explicit := map[string]bool{}
	for _, b := range bindings {
		if b.Family == "" {
			legacy[legacyTag(b)] = true
		} else {
			explicit[legacyTag(b)] = true
		}
	}
	var effective []Binding
	for _, b := range bindings {
		// Explicit records alongside a raw legacy record are Snapshot's
		// family-exact boundary. Do not expand contradictory old raw intent.
		if b.Family == "" && explicit[legacyTag(b)] {
			continue
		}
		effective = append(effective, b)
	}
	wanted := map[string]map[string]bool{}
	for _, b := range expandBindings(effective) {
		key := legacyTag(b)
		if wanted[key] == nil {
			wanted[key] = map[string]bool{}
		}
		wanted[key][b.Family] = true
	}
	for _, b := range expandBindings(effective) {
		r := ufwRule{b.Network, b.Port, "0.0.0.0/0", familyTag(b)}
		if b.Family == "ipv6" {
			r.to = "::/0"
		}
		generic := ufwRule{b.Network, b.Port, "any", legacyTag(b)}
		if legacy[legacyTag(b)] {
			// Keep legacy-only configurations cleanable by frozen old helpers:
			// qualify the family, but retain their exact project comment.
			r.tag = legacyTag(b)
			if !explicit[legacyTag(b)] {
				dual := wanted[legacyTag(b)]["ipv4"] && wanted[legacyTag(b)]["ipv6"]
				// Ensure may reuse an existing broad legacy rule but must never
				// create one for single-family intent. Journaled migration and
				// compensation still enforce their exact required families.
				if present[generic] && (ensureOnly || dual) || restore && dual {
					r.to = "any"
				}
			}
		}
		if out[r] == nil {
			out[r] = map[string]bool{}
		}
		out[r][b.Family] = true
	}
	return out
}

// Parse UFW's stored command form as well as its live status. Status alone
// loses whether a rule was generic or explicitly qualified to 0.0.0.0/0.
// Only exact allow/protocol/port/from-any/to-wildcard/comment identities qualify.
func parseUFWAdded(text string) map[ufwRule]bool {
	out := map[ufwRule]bool{}
	for _, line := range strings.Split(text, "\n") {
		p := strings.Fields(line)
		if len(p) < 3 || p[0] != "ufw" || p[1] != "allow" {
			continue
		}
		r := ufwRule{to: "any"}
		from := "any"
		valid := true
		for i := 2; i < len(p); i++ {
			switch p[i] {
			case "proto", "from", "to", "port", "comment":
				key := p[i]
				i++
				if i >= len(p) {
					valid = false
					break
				}
				v := strings.Trim(p[i], "'\"")
				switch key {
				case "proto":
					r.network = v
				case "from":
					from = v
				case "to":
					r.to = v
				case "port":
					r.port, _ = strconv.Atoi(v)
				case "comment":
					r.tag = v
				}
			default:
				parts := strings.Split(p[i], "/")
				if i == 2 && len(parts) == 2 {
					r.port, _ = strconv.Atoi(parts[0])
					r.network = parts[1]
				} else {
					valid = false
				}
			}
		}
		if valid && from == "any" && (r.to == "any" || r.to == "0.0.0.0/0" || r.to == "::/0") && (r.network == "tcp" || r.network == "udp") && r.port >= 1024 && r.port <= 65535 && r.tag != "" {
			out[r] = true
		}
	}
	return out
}
func ufwPhysical(status string, r ufwRule, family string) bool {
	return ufwStatusMatch(status, r, family, true)
}

// Ownership needs the exact ALLOW/comment identity. An insertion collision is
// different: UFW may replace a matching packet rule even when action, logging
// and comment differ. Never use ownership matching as the collision guard.
func ufwStatusMatch(status string, r ufwRule, family string, ownership bool) bool {
	for _, line := range strings.Split(status, "\n") {
		parts := strings.SplitN(line, "#", 2)
		tag := ""
		if len(parts) == 2 {
			tag = strings.TrimSpace(parts[1])
		}
		if ownership && tag != r.tag {
			continue
		}
		v6 := strings.Contains(parts[0], "(v6)")
		if v6 != (family == "ipv6") {
			continue
		}
		body := strings.ReplaceAll(parts[0], "(v6)", "")
		if !ownership {
			body = strings.ReplaceAll(strings.ReplaceAll(body, "(log)", ""), "(log-all)", "")
		}
		p := strings.Fields(body)
		// Ignore numbered status prefixes when present.
		if len(p) > 0 && p[0] == "[" {
			if len(p) < 3 {
				continue
			}
			p = p[2:]
		}
		if len(p) < 3 || p[0] != fmt.Sprintf("%d/%s", r.port, r.network) {
			continue
		}
		i := 1
		if p[i] == "0.0.0.0/0" || p[i] == "::/0" {
			expected := "0.0.0.0/0"
			if family == "ipv6" {
				expected = "::/0"
			}
			if p[i] != expected || r.to != "any" && p[i] != r.to {
				continue
			}
			i++
		}
		if i >= len(p) {
			continue
		}
		if ownership {
			if p[i] != "ALLOW" {
				continue
			}
		} else if p[i] != "ALLOW" && p[i] != "DENY" && p[i] != "REJECT" && p[i] != "LIMIT" {
			continue
		}
		i++
		if i < len(p) && p[i] == "IN" {
			i++
		}
		if i == len(p)-1 && (p[i] == "Anywhere" || family == "ipv4" && p[i] == "0.0.0.0/0" || family == "ipv6" && p[i] == "::/0") {
			return true
		}
	}
	return false
}
func (f Firewall) ufwState(ctx context.Context) (map[ufwRule]bool, string, error) {
	added, err := f.Run(ctx, "ufw", "show", "added")
	if err != nil {
		return nil, "", err
	}
	status, err := f.Run(ctx, "ufw", "status")
	if err != nil {
		return nil, "", err
	}
	if !strings.Contains(string(status), "Status: active") {
		return nil, "", errors.New("UFW became inactive during project rule update")
	}
	rules := parseUFWAdded(string(added))
	// UFW's get_command canonicalizes BOTH generic and qualified wildcard
	// rules to `allow port/proto`. Recover explicit identity only when the
	// exact family comment and live family agree; never reinterpret a legacy
	// generic comment as IPv4-only. A mismatched opposite-family rule is not
	// ours to relabel/delete through this qualified identity.
	for r := range rules {
		if r.to != "any" {
			continue
		}
		if r.tag == legacyTag(Binding{Network: r.network, Port: r.port}) {
			v4, v6 := ufwPhysical(string(status), r, "ipv4"), ufwPhysical(string(status), r, "ipv6")
			if v4 != v6 {
				delete(rules, r)
				if v4 {
					r.to = "0.0.0.0/0"
				} else {
					r.to = "::/0"
				}
				rules[r] = true
			}
			continue
		}
		for _, family := range []string{"ipv4", "ipv6"} {
			b := Binding{Network: r.network, Port: r.port, Family: family}
			if r.tag != familyTag(b) {
				continue
			}
			opposite, to := "ipv6", "0.0.0.0/0"
			if family == "ipv6" {
				opposite, to = "ipv4", "::/0"
			}
			if !ufwPhysical(string(status), r, opposite) {
				delete(rules, r)
				r.to = to
				rules[r] = true
			}
		}
	}
	return rules, string(status), nil
}

func ufwEquivalent(status string, r ufwRule, family string) bool {
	return ufwStatusMatch(status, r, family, false)
}

// UFW reconstructs wildcard commands without retaining their original family
// qualifier. Treat canonical generic/qualified spellings as the same physical
// identities, while checking live required families separately. For deletion,
// either surviving half means a generic deletion is still incomplete.
func ufwStoredRule(rules map[ufwRule]bool, r ufwRule) bool {
	if rules[r] {
		return true
	}
	// Only legacy comments can intentionally cover both actual families.
	// A generic rule bearing an explicit family comment is a mismatched
	// identity, not permission to claim or relabel its other physical half.
	if r.tag != legacyTag(Binding{Network: r.network, Port: r.port}) {
		return false
	}
	if r.to != "any" {
		r.to = "any"
		return rules[r]
	}
	r.to = "0.0.0.0/0"
	v4 := rules[r]
	r.to = "::/0"
	return v4 || rules[r]
}

func (f Firewall) reconcileUFW(ctx context.Context, old, next []Binding, remove, restore, ensureOnly bool) error {
	rules, _, err := f.ufwState(ctx)
	if err != nil {
		return err
	}
	allowed := ufwDefinitions(append(append([]Binding(nil), old...), next...))
	desired := ufwDesired(next, rules, restore, ensureOnly)
	// Generic and qualified rules can coalesce in UFW. Remove obsolete OWNED
	// definitions first, then verify each insertion's stored and live identity.
	// The raw journal and Snapshot allow compensation after either step fails.
	for r := range allowed {
		if _, keep := desired[r]; !ensureOnly && rules[r] && (remove || !keep) {
			if _, err = f.Run(ctx, r.args(true)...); err != nil {
				return err
			}
			state, _, e := f.ufwState(ctx)
			if e != nil {
				return e
			}
			if ufwStoredRule(state, r) {
				return errors.New("UFW project rule deletion could not be verified")
			}
		}
	}
	for r, families := range desired {
		state, status, e := f.ufwState(ctx)
		if e != nil {
			return e
		}
		if !ufwStoredRule(state, r) {
			// Some UFW versions replace an equivalent rule's comment rather
			// than skipping insertion. Never attempt insertion in that case:
			// post-checking ownership would be too late to protect the owner.
			check := families
			if r.to == "any" {
				check = map[string]bool{"ipv4": true, "ipv6": true}
			}
			for family := range check {
				if ufwEquivalent(status, r, family) {
					return errors.New("refusing to relabel an existing equivalent UFW rule")
				}
			}
			if _, e = f.Run(ctx, r.args(false)...); e != nil {
				return fmt.Errorf("UFW project rule update failed: %w", e)
			}
			state, status, e = f.ufwState(ctx)
			if e != nil {
				return e
			}
		}
		if !ufwStoredRule(state, r) {
			return errors.New("UFW did not create the exact project rule (foreign equivalent/coalesced rule)")
		}
		for family := range families {
			if !ufwPhysical(status, r, family) {
				return fmt.Errorf("UFW project %s allowance was not installed", family)
			}
		}
	}
	return nil
}
