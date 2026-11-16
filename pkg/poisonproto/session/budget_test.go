package session

import "testing"

func TestBudgetControllerGrowsAfterCleanRetires(t *testing.T) {
	b := newBudgetController(1000, 2000, true)
	for i := 0; i < growAfterCleanRetires-1; i++ {
		b.onCleanRetire()
	}
	if b.curMax != 2000 {
		t.Fatalf("budget grew too early: curMax=%d", b.curMax)
	}
	b.onCleanRetire()
	if b.curMax != 4000 || b.curMin != 2000 {
		t.Fatalf("budget did not double after %d clean retires: min=%d max=%d", growAfterCleanRetires, b.curMin, b.curMax)
	}
}

func TestBudgetControllerFreezeResetsRange(t *testing.T) {
	b := newBudgetController(1000, 2000, true)
	for i := 0; i < growAfterCleanRetires; i++ {
		b.onCleanRetire()
	}
	if b.curMax == 2000 {
		t.Fatal("setup: expected growth before testing reset")
	}
	b.onFreeze()
	if b.curMin != 1000 || b.curMax != 2000 || b.unlimited {
		t.Fatalf("onFreeze did not reset to configured range: min=%d max=%d unlimited=%v", b.curMin, b.curMax, b.unlimited)
	}
}

func TestBudgetControllerEventuallyUnlimited(t *testing.T) {
	b := newBudgetController(1000, 2000, true)
	for i := 0; i < 1000; i++ {
		b.onCleanRetire()
		if b.unlimited {
			break
		}
	}
	if !b.unlimited {
		t.Fatal("budget never reached unlimited after many clean retires")
	}
	if d := b.draw(); d != 0 {
		t.Fatalf("draw() should signal unlimited with 0, got %d", d)
	}
}

func TestBudgetControllerNonAdaptiveNeverGrows(t *testing.T) {
	b := newBudgetController(1000, 2000, false)
	for i := 0; i < 100; i++ {
		b.onCleanRetire()
	}
	if b.curMax != 2000 || b.unlimited {
		t.Fatalf("non-adaptive controller grew: min=%d max=%d unlimited=%v", b.curMin, b.curMax, b.unlimited)
	}
}

func TestBudgetControllerDrawWithinRange(t *testing.T) {
	b := newBudgetController(1000, 2000, true)
	for i := 0; i < 200; i++ {
		d := b.draw()
		if d < 1000 || d > 2000 {
			t.Fatalf("draw() out of range: %d", d)
		}
	}
}
