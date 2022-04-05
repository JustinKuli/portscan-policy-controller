/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package scriptout

import (
	"fmt"
	"strconv"
	"strings"
)

func (run NMapRun) GetHostsUp() map[string]Host {
	hosts := make(map[string]Host)
	for _, h := range run.Hosts {
		if h.Status.State == "up" {
			hosts[h.Address.Addr] = h
		}
	}
	return hosts
}

func (run NMapRun) GetActivePorts(host string) map[string]PortDetail {
	ports := make(map[string]PortDetail)
	for _, pd := range run.GetHostsUp()[host].Ports.Ports {
		ports[pd.PortID] = pd
	}
	return ports
}

func (run NMapRun) GetTLSTables(host, portID string) map[string]ScriptTable {
	tables := make(map[string]ScriptTable)
	for _, tbl := range run.GetActivePorts(host)[portID].Script.Tables {
		tables[tbl.Key] = tbl
	}
	return tables
}

type CipherInfo struct {
	KexInfo  string
	Name     string
	Strength string
}

func (t ScriptTable) CipherInfo() CipherInfo {
	elems := t.Elements()

	return CipherInfo{
		KexInfo:  elems["kex_info"],
		Name:     elems["name"],
		Strength: elems["strength"],
	}
}

func (t ScriptTable) Elements() map[string]string {
	elems := make(map[string]string)
	for _, ele := range t.Elems {
		elems[ele.Key] = ele.Value
	}
	return elems
}

func (run NMapRun) GetCiphers(host, portID, tlsVersion string) []CipherInfo {
	ciphers := make([]CipherInfo, 0)

	for _, subTable := range run.GetTLSTables(host, portID)[tlsVersion].Tables {
		if subTable.Key != "ciphers" {
			continue
		}
		for _, cipherTable := range subTable.Tables {
			ciphers = append(ciphers, cipherTable.CipherInfo())
		}
	}

	return ciphers
}

func (run NMapRun) ScannedServices() (map[int]bool, error) {
	services := make(map[int]bool)

	for _, portOrRange := range strings.Split(run.ScanInfo.Services, ",") {
		ends := strings.Split(portOrRange, "-")
		switch len(ends) {
		case 1: // single port
			port, err := strconv.Atoi(ends[0])
			if err != nil {
				return services, err
			}
			services[port] = true

		case 2: // range
			start, err := strconv.Atoi(ends[0])
			if err != nil {
				return services, err
			}
			end, err := strconv.Atoi(ends[1])
			if err != nil {
				return services, err
			}

			for port := start; port <= end; port++ {
				services[port] = true
			}

		default:
			return services, fmt.Errorf("unexpected value in scaninfo.services: '%v'", portOrRange)
		}
	}

	return services, nil
}

func (run NMapRun) LeastStrength(host, portID string) string {
	for _, elem := range run.GetActivePorts(host)[portID].Script.Elems {
		if elem.Key != "least strength" {
			continue
		}
		return elem.Value
	}
	return ""
}

func (run NMapRun) LeastStrengthAll() (rune, error) {
	worstFound := 'A' - 1 // larger means worse, so this is stronger than 'A'
	var err error

	for _, host := range run.GetHostsUp() {
		for _, port := range host.Ports.Ports {
			for _, elem := range port.Script.Elems {
				if elem.Key != "least strength" {
					continue
				}
				if len(elem.Value) < 1 {
					// TODO: improve this error with a specific type for better handling?
					err = fmt.Errorf("unexpected empty 'least strength' elem found in report")
					continue
				}
				found := []rune(elem.Value)[0]
				if found > worstFound {
					worstFound = found
				}
			}
		}
	}

	return worstFound, err
}

type FlattenedCipherInfo struct {
	HostAddr   string
	PortID     string
	TLSVersion string
	CipherInfo
}

func (run NMapRun) GetFlatCiphers() []FlattenedCipherInfo {
	out := make([]FlattenedCipherInfo, 0)
	for hostAddr, host := range run.GetHostsUp() {
		for _, port := range host.Ports.Ports {
			portId := port.PortID
			for _, tlsTable := range port.Script.Tables {
				tlsVersion := tlsTable.Key
				for _, subtable := range tlsTable.Tables {
					if subtable.Key != "ciphers" {
						continue
					}
					for _, cipherTable := range subtable.Tables {
						out = append(out, FlattenedCipherInfo{
							HostAddr:   hostAddr,
							PortID:     portId,
							TLSVersion: tlsVersion,
							CipherInfo: cipherTable.CipherInfo(),
						})
					}
				}
			}
		}
	}
	return out
}
