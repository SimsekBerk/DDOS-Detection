package engine

import (
	"fmt"

	"github.com/SimsekBerk/DDOS-Detection/internal/config"
)

// UpdateConfig applies engine parameters and protected objects at runtime.
// Series, baselines and incidents of objects that still exist (matched by
// name) are kept; series of removed objects are dropped (active vectors end).
// Restart-only settings (data_dir, rules_dir, recent_flows) are ignored here.
func (e *Engine) UpdateConfig(cfg *config.Config) error {
	set := e.Rules()
	for _, o := range cfg.Objects {
		if _, ok := set.Profiles[o.Profile]; !ok {
			return fmt.Errorf("korunan nesne %q bilinmeyen profil kullanıyor: %q", o.Name, o.Profile)
		}
	}
	return e.Do(func() {
		now := e.clock()
		old := e.objs
		next := newObjectTable(cfg.Objects)
		idMap := map[int32]int32{}
		byName := map[string]int32{}
		for _, o := range next.objects {
			byName[o.Name] = o.ID
		}
		for _, o := range old.objects {
			if id, ok := byName[o.Name]; ok {
				idMap[o.ID] = id
			}
		}
		remapped := map[seriesKey]*series{}
		for k, s := range e.series {
			nid, ok := idMap[k.obj]
			if !ok {
				if s.active {
					e.endVector(s, e.set.Rules[k.rule], now)
				}
				continue
			}
			k.obj = nid
			remapped[k] = s
		}
		e.series = remapped
		e.totals.remap(len(next.objects), idMap)
		e.incidents.remapObjects(idMap)

		e.objs = next
		e.objsPtr.Store(next)
		e.cfg = cfg
		e.cfgPtr.Store(cfg)
		e.window = int64(cfg.Engine.Window.Seconds())
		e.maxSpread = max(1, int64(cfg.Engine.MaxFlowSpread.Seconds()))
		e.tau = cfg.Engine.BaselineTau.Seconds()
		e.learn = cfg.Engine.BaselineLearn.Seconds()
		e.incidents.setReopen(cfg.Engine.IncidentReopen.Duration)
		e.applyRules(e.set) // effective thresholds and classifier for the new objects
	})
}
