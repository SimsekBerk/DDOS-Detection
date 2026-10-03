package config

import (
	"os"
	"testing"
)

func TestExampleConfigsParse(t *testing.T) {
	for _, f := range []string{"../../config.example.yaml", "../../config.demo.yaml", "../../config.preprod.example.yaml"} {
		if _, err := Load(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	c, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c.Notifications.Channels = []ChannelConfig{{Name: "noc", Type: "slack", Enabled: true, URL: "https://hooks.slack.com/x", MinSeverity: "high"}}
	if err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	b, err := Marshal(c, "test")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Parse(b)
	if err != nil {
		t.Fatalf("re-parse: %v\n%s", err, b)
	}
	if c2.Objects[0].LinkCapacity != c.Objects[0].LinkCapacity || c2.Engine.Window != c.Engine.Window || len(c2.Notifications.Channels) != 1 {
		t.Errorf("round trip mismatch")
	}
}

func TestSecretsMaskAndRestore(t *testing.T) {
	c, _ := Load("../../config.example.yaml")
	c.API.Password = "s3cret"
	c.Notifications.Channels = []ChannelConfig{{Name: "tg", Type: "telegram", BotToken: "123:abc", ChatID: "1", MinSeverity: "high"}}
	m := c.Masked()
	if m.API.Password != SecretMask || m.Notifications.Channels[0].BotToken != SecretMask {
		t.Fatal("secrets not masked")
	}
	if c.API.Password != "s3cret" {
		t.Fatal("mask modified the original")
	}
	m.RestoreSecrets(c)
	if m.API.Password != "s3cret" || m.Notifications.Channels[0].BotToken != "123:abc" {
		t.Fatal("secrets not restored")
	}
}

func TestValidationMessages(t *testing.T) {
	b, _ := os.ReadFile("../../config.example.yaml")
	c, _ := Parse(b)
	c.Objects[0].Prefixes = []string{"not-a-prefix"}
	if err := c.Normalize(); err == nil {
		t.Fatal("expected prefix error")
	}
}
