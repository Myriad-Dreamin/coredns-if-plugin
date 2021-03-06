package ifv6_local

import (
	"os"
	"time"

	"github.com/coredns/coredns/plugin/transfer"
)

// Reload reloads a zone when it is changed on disk. If z.NoReload is true, no reloading will be done.
func (z *Zone) Reload(t *transfer.Transfer) error {
	if z.ReloadInterval == 0 {
		return nil
	}
	tick := time.NewTicker(z.ReloadInterval)

	go func() {
		for {
			select {
			case <-tick.C:
				zFile := z.File()
				serial := z.SOASerialIfDefined()
				serial = z.ifv6Watcher.Watch(serial)

				reader, err := os.Open(zFile)
				if err != nil {
					log.Errorf("Failed to open zone %q in %q: %v", z.origin, zFile, err)
					continue
				}

				serial = z.SOASerialIfDefined()
				zone, err := Parse(reader, z.origin, zFile, serial)
				reader.Close()
				if err != nil {
					if _, ok := err.(*serialErr); !ok {
						log.Errorf("Parsing zone %q: %v", z.origin, err)
					}
					continue
				}

				// copy elements we need
				z.Lock()
				z.Apex = zone.Apex
				z.Tree = zone.Tree
				z.Unlock()

				log.Infof("Successfully reloaded zone %q in %q with %d SOA serial", z.origin, zFile, z.Apex.SOA.Serial)
				if t != nil {
					if err := t.Notify(z.origin); err != nil {
						log.Warningf("Failed sending notifies: %s", err)
					}
				}

			case <-z.reloadShutdown:
				tick.Stop()
				return
			}
		}
	}()
	return nil
}

// SOASerialIfDefined returns the SOA's serial if the zone has a SOA record in the Apex, or -1 otherwise.
func (z *Zone) SOASerialIfDefined() int64 {
	z.RLock()
	defer z.RUnlock()
	if z.Apex.SOA != nil {
		return int64(z.Apex.SOA.Serial)
	}
	return -1
}
