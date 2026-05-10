//go:build guest_windows

package main

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/gdi"
)

func TestPrintPagePath(t *testing.T) {
	if got := printPagePath("document.png", 1); got != "document.png" {
		t.Fatalf("first page path = %q", got)
	}
	if got := printPagePath("document.png", 2); got != "document-page-2.png" {
		t.Fatalf("second page path = %q", got)
	}
	if got := printCopyPath("document.png", 1, 2); got != "document-copy-2.png" {
		t.Fatalf("second copy path = %q", got)
	}
	if got := printCopyPath("document.png", 2, 2); got != "document-page-2-copy-2.png" {
		t.Fatalf("second page copy path = %q", got)
	}
}

func TestPrintJobLifecycle(t *testing.T) {
	job := &printJobState{}
	if job.beginPage() || job.canEndDoc() {
		t.Fatal("job accepted a page or EndDoc before StartDoc")
	}
	if !job.beginDoc(true) || job.beginDoc(true) {
		t.Fatal("StartDoc transition is incorrect")
	}
	if !job.beginPage() || job.beginPage() || job.canEndDoc() {
		t.Fatal("StartPage transition is incorrect")
	}
	if !job.completePage() || job.completePage() || job.page != 1 {
		t.Fatal("EndPage transition is incorrect")
	}
	if !job.canEndDoc() {
		t.Fatal("EndDoc was rejected after a completed page")
	}
}

func TestPrintInformationContextRejectsDocument(t *testing.T) {
	job := &printJobState{infoOnly: true}
	if job.beginDoc(true) {
		t.Fatal("information context accepted StartDoc")
	}
}

func TestPrintInformationContextDoesNotDraw(t *testing.T) {
	surface := gdi.NewSurface(64, 32)
	surface.FillRect(0, 0, surface.Width, surface.Height, 0xFFFFFF)
	dc := gdi.NewMemoryDC()
	dc.Target = surface
	dc.InfoOnly = true
	dc.TextOut(0, 14, "hidden", false)
	for i, value := range surface.Pix {
		if i%4 == 3 {
			continue
		}
		if value != 0xFF {
			t.Fatalf("information context changed pixel byte %d", i)
		}
	}
}

func TestSavePrintSurface(t *testing.T) {
	surface := gdi.NewSurface(8, 8)
	surface.FillRect(0, 0, 8, 8, 0xFFFFFF)
	surface.FillRect(2, 2, 6, 6, 0x000000)
	path := filepath.Join(t.TempDir(), "page.png")
	if err := savePrintSurface(path, surface); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	img, err := png.Decode(file)
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds().Dx() != 8 || img.Bounds().Dy() != 8 {
		t.Fatalf("image bounds = %v", img.Bounds())
	}
}

func TestSavePrintSurfaceReportsWriteFailure(t *testing.T) {
	surface := gdi.NewSurface(1, 1)
	path := filepath.Join(t.TempDir(), "missing", "page.png")
	if err := savePrintSurface(path, surface); err == nil {
		t.Fatal("savePrintSurface accepted an unavailable directory")
	}
}
