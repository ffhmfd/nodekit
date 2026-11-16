package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"nodekit/internal/model"
	"nodekit/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func trafficConfig(t *testing.T, c model.Config, multiplier int) model.Config {
	t.Helper()
	data, _ := json.Marshal(map[string]int{"traffic_multiplier": multiplier})
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTrafficMultiplierCLIAndStatus(t *testing.T) {
	p, db, _ := ipv6CLIFixture(t)
	initial := protocolRecord(t, db)
	for _, step := range []struct{ value, upload, total string }{{"2", "246", "246"}, {"1", "123", "123"}} {
		var out bytes.Buffer
		if err := editWithIPv6Deps(context.Background(), p, []string{"config", "set", "traffic-multiplier", step.value}, &out, ipv6TestDeps()); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "刷新订阅") {
			t.Fatal("missing refresh advice", out.String())
		}
		out.Reset()
		if err := execute(context.Background(), p, []string{"status"}, strings.NewReader(""), &out); err != nil {
			t.Fatal(err)
		}
		for _, text := range []string{"流量计量: " + step.value + " 倍", "已用上传: " + step.upload + " B", "已用合计: " + step.total + " B"} {
			if !strings.Contains(out.String(), text) {
				t.Errorf("missing %q in %s", text, out.String())
			}
		}
		if !reflect.DeepEqual(protocolRecord(t, db).Meter, initial.Meter) {
			t.Fatal("switch changed raw counters")
		}
	}
	for _, value := range []string{"0", "3", "-1", "1.5", "two"} {
		before := protocolRecord(t, db)
		if err := editWithIPv6Deps(context.Background(), p, []string{"config", "set", "traffic-multiplier", value}, &bytes.Buffer{}, ipv6TestDeps()); err == nil {
			t.Fatal("accepted", value)
		}
		if !reflect.DeepEqual(protocolRecord(t, db), before) {
			t.Fatal("invalid input changed state")
		}
	}
}

func TestTrafficMultiplierMenu(t *testing.T) {
	p, db, _ := ipv6CLIFixture(t)
	for _, step := range []struct{ input, upload string }{{"25\nbad\n3\n2\n0\n", "246"}, {"25\n1\n0\n", "123"}} {
		var out, errOut bytes.Buffer
		menu(context.Background(), p, strings.NewReader(step.input), &out, &errOut)
		if errOut.Len() != 0 || !strings.Contains(out.String(), "刷新订阅") {
			t.Fatal(errOut.String(), out.String())
		}
		out.Reset()
		if err := execute(context.Background(), p, []string{"status"}, strings.NewReader(""), &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "已用上传: "+step.upload+" B") {
			t.Fatal(out.String())
		}
	}
	before := protocolRecord(t, db)
	for _, input := range []string{"25\n0\n0\n", "25\n"} {
		menu(context.Background(), p, strings.NewReader(input), &bytes.Buffer{}, &bytes.Buffer{})
		if !reflect.DeepEqual(protocolRecord(t, db), before) {
			t.Fatal("cancel changed config")
		}
	}
}

func TestTrafficMultiplierStatusLargeTotal(t *testing.T) {
	p, db, _ := ipv6CLIFixture(t)
	if err := db.Update(func(r *store.Record) error {
		r.Config = trafficConfig(t, r.Config, 2)
		r.Meter.Upload, r.Meter.Download = math.MaxInt64, math.MaxInt64
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := execute(context.Background(), p, []string{"status"}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "已用合计: 18446744073709551615 B") {
		t.Fatal("combined counter wrapped", out.String())
	}
}

func TestTrafficMultiplierImportLegacyResetsToDefault(t *testing.T) {
	p, db, legacy := ipv6CLIFixture(t)
	if err := db.Update(func(r *store.Record) error { r.Config = trafficConfig(t, r.Config, 2); return nil }); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(file, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := editWithIPv6Deps(context.Background(), p, []string{"config", "apply", file}, &bytes.Buffer{}, ipv6TestDeps()); err != nil {
		t.Fatal(err)
	}
	r := protocolRecord(t, db)
	if r.Config.EffectiveTrafficMultiplier() != 1 || r.Meter.Upload != 123 {
		t.Fatal("legacy import inherited multiplier or reset usage")
	}
}

func TestTrafficMultiplierCompatibility(t *testing.T) {
	c, _ := model.New()
	c = trafficConfig(t, c, 2)
	for _, capable := range []bool{false, true} {
		features := ""
		if capable {
			features = `,"features":["traffic-multiplier-v1"]`
		}
		bin := filepath.Join(t.TempDir(), "helper")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\necho '{\"subscription_modes\":[\"direct\"]"+features+"}'\n"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := checkReleaseCompatibility(context.Background(), c, bin); (err == nil) != capable {
			t.Fatalf("capable=%v: %v", capable, err)
		}
	}
	p := makePaths(t.TempDir(), "")
	if err := os.MkdirAll(p.Etc, 0700); err != nil {
		t.Fatal(err)
	}
	m := hostManifest{}
	if err := saveRetainedRequirements(p, &m, c); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(m.RequiredFeatures, "traffic-multiplier-v1") {
		t.Fatal("retained install lost multiplier requirement")
	}
	if err := checkRetainedCompatibility(context.Background(), p, "/does/not/exist"); err == nil {
		t.Fatal("retained 2x config accepted unknown helper")
	}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"capabilities"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatal(code, errOut.String())
	}
	var caps capabilities
	if err := json.Unmarshal(out.Bytes(), &caps); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(caps.Features, "traffic-multiplier-v1") {
		t.Fatal("missing capability")
	}
}
