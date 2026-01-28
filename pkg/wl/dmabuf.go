package wl

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	DrmFormatXRGB8888 = uint32('X') | uint32('R')<<8 | uint32('2')<<16 | uint32('4')<<24
	DrmFormatARGB8888 = uint32('A') | uint32('R')<<8 | uint32('2')<<16 | uint32('4')<<24
)

type WlWindow = Window

func (d *Display) recordDmabufFormat(format uint32, modifier uint64) {
	if d.dmabufFormats == nil {
		d.dmabufFormats = map[uint32]map[uint64]struct{}{}
	}
	mods := d.dmabufFormats[format]
	if mods == nil {
		mods = map[uint64]struct{}{}
		d.dmabufFormats[format] = mods
	}
	mods[modifier] = struct{}{}
}

func (d *Display) DmabufAvailable() bool {
	return d != nil && d.dmabufID != 0
}

func (d *Display) SupportsDmabufFormat(format uint32, modifier uint64) bool {
	if d == nil || len(d.dmabufFormats) == 0 {
		return false
	}
	mods := d.dmabufFormats[format]
	if len(mods) == 0 {
		return false
	}
	if _, ok := mods[modifier]; ok {
		return true
	}
	if modifier == 0 {
		_, ok := mods[0]
		return ok
	}
	return false
}

func (w *Window) HasDmabufSupport() bool {
	return w != nil && w.disp != nil && w.disp.DmabufAvailable()
}

func (w *Window) SupportsDmabufFormat(format uint32, modifier uint64) bool {
	return w != nil && w.disp != nil && w.disp.SupportsDmabufFormat(format, modifier)
}

func (w *Window) DmabufReady(width, height, stride, format uint32, modifier uint64) bool {
	return w != nil &&
		w.dmabufID != 0 &&
		w.dmabufWidth == width &&
		w.dmabufHeight == height &&
		w.dmabufStride == stride &&
		w.dmabufFormat == format &&
		w.dmabufModifier == modifier
}

func (w *Window) destroyDmabufBuffer() {
	if w == nil {
		return
	}
	if w.dmabufID != 0 && w.disp != nil {
		w.disp.send(w.dmabufID, 0)
		delete(w.disp.objects, w.dmabufID)
	}
	w.dmabufID = 0
	w.dmabufWidth = 0
	w.dmabufHeight = 0
	w.dmabufStride = 0
	w.dmabufFormat = 0
	w.dmabufModifier = 0
	w.dmabufParamsID = 0
}

func (w *Window) CreateDmabufBuffer(fd int, width, height, stride uint32, format uint32, modifier uint64) error {
	if w == nil || w.disp == nil {
		if fd >= 0 {
			unix.Close(fd)
		}
		return fmt.Errorf("wayland: nil window")
	}
	if fd < 0 {
		return fmt.Errorf("wayland: invalid dmabuf fd")
	}
	defer unix.Close(fd)
	d := w.disp
	if d.dmabufID == 0 {
		return fmt.Errorf("wayland: zwp_linux_dmabuf_v1 unavailable")
	}

	w.destroyDmabufBuffer()
	w.dmabufCreateErr = nil

	paramsID := d.alloc(kindLinuxBufferParams)
	d.dmabufParams[paramsID] = w
	w.dmabufParamsID = paramsID
	w.dmabufWidth = width
	w.dmabufHeight = height
	w.dmabufStride = stride
	w.dmabufFormat = format
	w.dmabufModifier = modifier

	if err := d.send(d.dmabufID, 1, pu32(paramsID)); err != nil { // opcode 1 = create_params
		delete(d.dmabufParams, paramsID)
		delete(d.objects, paramsID)
		w.destroyDmabufBuffer()
		return err
	}
	if err := d.sendFD(paramsID, 1, fd, // opcode 1 = add
		pu32(0),
		pu32(0),
		pu32(stride),
		pu32(uint32(modifier>>32)),
		pu32(uint32(modifier)),
	); err != nil {
		delete(d.dmabufParams, paramsID)
		delete(d.objects, paramsID)
		w.destroyDmabufBuffer()
		return err
	}
	if err := d.send(paramsID, 2, pi32(int32(width)), pi32(int32(height)), pu32(format), pu32(0)); err != nil {
		delete(d.dmabufParams, paramsID)
		delete(d.objects, paramsID)
		w.destroyDmabufBuffer()
		return err
	}

	for w.dmabufID == 0 && w.dmabufCreateErr == nil {
		if _, err := d.dispatchOne(); err != nil {
			delete(d.dmabufParams, paramsID)
			delete(d.objects, paramsID)
			w.destroyDmabufBuffer()
			return err
		}
	}
	if w.dmabufCreateErr != nil {
		err := w.dmabufCreateErr
		w.dmabufCreateErr = nil
		w.destroyDmabufBuffer()
		return err
	}
	return nil
}

func (w *Window) CommitDmabuf() {
	if w == nil || w.disp == nil || w.dmabufID == 0 {
		return
	}
	height := w.dmabufHeight
	if height == 0 {
		height = uint32(w.Height + w.TitleBarH)
	}
	width := w.dmabufWidth
	if width == 0 {
		width = uint32(w.Width)
	}
	w.disp.send(w.surfaceID, 1, pu32(w.dmabufID), pi32(0), pi32(0))
	w.disp.send(w.surfaceID, 9, pi32(0), pi32(0), pi32(int32(width)), pi32(int32(height)))
	w.disp.send(w.surfaceID, 6)
}
