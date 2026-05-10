package wl

import (
	"os"
	"testing"
)

func TestOwnedWindowDestroyAndRecreate(t *testing.T) {
	if os.Getenv("RAVEN_WL_INTEGRATION") != "1" {
		t.Skip("set RAVEN_WL_INTEGRATION=1 to run against an isolated compositor")
	}
	display, err := Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer display.Close()
	mainWindow, err := display.CreateWindow("main", 320, 200, 0)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := display.CreateOwnedWindow("first", 160, 100, 0, mainWindow)
	if err != nil {
		t.Fatal(err)
	}
	owned.Destroy()
	if _, err := display.CreateOwnedWindow("second", 160, 100, 0, mainWindow); err != nil {
		t.Fatalf("recreate owned window: %v", err)
	}
}
