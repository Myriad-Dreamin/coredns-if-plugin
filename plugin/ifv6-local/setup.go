package ifv6_local

import (
	"github.com/Myriad-Dreamin/coredns-plugin-ifv6/core"
	"os"
	"path/filepath"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/upstream"
	"github.com/coredns/coredns/plugin/transfer"
)

func init() { plugin.Register("ifv6_local", setup) }

func setup(c *caddy.Controller) error {
	zones, err := fileParse(c)
	if err != nil {
		return plugin.Error("ifv6_local", err)
	}

	f := File{Zones: zones}
	// get the transfer plugin, so we can send notifies and send notifies on startup as well.
	c.OnStartup(func() error {
		t := dnsserver.GetConfig(c).Handler("transfer")
		if t == nil {
			return nil
		}
		f.transfer = t.(*transfer.Transfer) // if found this must be OK.
		go func() {
			for _, n := range zones.Names {
				f.transfer.Notify(n)
			}
		}()
		return nil
	})

	c.OnRestartFailed(func() error {
		t := dnsserver.GetConfig(c).Handler("transfer")
		if t == nil {
			return nil
		}
		go func() {
			for _, n := range zones.Names {
				f.transfer.Notify(n)
			}
		}()
		return nil
	})

	for _, n := range zones.Names {
		z := zones.Z[n]
		c.OnShutdown(z.OnShutdown)
		c.OnStartup(func() error {
			z.StartupOnce.Do(func() { z.Reload(f.transfer) })
			return nil
		})
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		f.Next = next
		return f
	})

	return nil
}

func fileParse(c *caddy.Controller) (Zones, error) {
	z := make(map[string]*Zone)
	names := []string{}

	config := dnsserver.GetConfig(c)

	var openErr error
	reload := 1 * time.Minute

	for c.Next() {
		// file db.file [zones...]
		if !c.NextArg() {
			return Zones{}, c.ArgErr()
		}
		interfaceName := c.Val()
		if !c.NextArg() {
			return Zones{}, c.ArgErr()
		}
		mappingDomain := c.Val()
		if !c.NextArg() {
			return Zones{}, c.ArgErr()
		}
		dir := c.Val()
		commonFilePrefix := filepath.Join(dir, mappingDomain)
		privateFileName := commonFilePrefix + ".private.dns"
		publicFileName := commonFilePrefix + ".dns"
		watcher := &core.InterfaceIPV6Watcher{
			InterfaceName: interfaceName,
			MappingDomain: mappingDomain,
			DNSFileDir:    dir,
			PrivateFile:   privateFileName,
			PublicFile:    publicFileName,
		}

		origins := plugin.OriginsFromArgsOrServerBlock(c.RemainingArgs(), c.ServerBlockKeys)
		if !filepath.IsAbs(privateFileName) && config.Root != "" {
			privateFileName = filepath.Join(config.Root, privateFileName)
		}

		reader, err := os.Open(privateFileName)
		if err != nil {
			openErr = err
		}

		for i := range origins {
			zz := NewZone(origins[i], privateFileName)
			zz.ifv6Watcher = watcher
			z[origins[i]] = zz
			if openErr == nil {
				reader.Seek(0, 0)
				zone, err := Parse(reader, origins[i], privateFileName, 0)
				if err != nil {
					return Zones{}, err
				}
				zone.ifv6Watcher = watcher
				z[origins[i]] = zone
			}
			names = append(names, origins[i])
		}

		for c.NextBlock() {
			switch c.Val() {
			case "reload":
				d, err := time.ParseDuration(c.RemainingArgs()[0])
				if err != nil {
					return Zones{}, plugin.Error("ifv6_local", err)
				}
				reload = d
			case "upstream":
				// remove soon
				c.RemainingArgs()

			default:
				return Zones{}, c.Errf("unknown property '%s'", c.Val())
			}
		}
	}

	for origin := range z {
		z[origin].ReloadInterval = reload
		z[origin].Upstream = upstream.New()
	}

	if openErr != nil {
		if reload == 0 {
			// reload hasn't been set make this a fatal error
			return Zones{}, plugin.Error("ifv6_local", openErr)
		}
		log.Warningf("Failed to open %q: trying again in %s", openErr, reload)

	}
	return Zones{Z: z, Names: names}, nil
}
