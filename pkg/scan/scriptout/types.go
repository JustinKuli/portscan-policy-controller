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

import "encoding/xml"

type NMapRun struct {
	XMLName  xml.Name `xml:"nmaprun"`
	Args     string   `xml:"args,attr"`
	Start    string   `xml:"start,attr"` // unix timestamp
	Version  string   `xml:"version,attr"`
	ScanInfo ScanInfo `xml:"scaninfo"`
	Hosts    []Host   `xml:"host"`
	RunStats RunStats `xml:"runstats"`
}

type ScanInfo struct {
	XMLName     xml.Name `xml:"scaninfo"`
	Protocol    string   `xml:"protocol,attr"`
	NumServices int      `xml:"numservices,attr"`
	Services    string   `xml:"services,attr"`
}

type Host struct {
	XMLName   xml.Name    `xml:"host"`
	Status    HostStatus  `xmk:"status"`
	Address   HostAddress `xml:"address"`
	Hostnames Hostnames   `xml:"hostnames"`
	Ports     HostPorts   `xml:"ports"`
}

type HostStatus struct {
	XMLName xml.Name `xml:"status"`
	State   string   `xml:"state,attr"`
}

type HostAddress struct {
	XMLName  xml.Name `xml:"address"`
	Addr     string   `xml:"addr,attr"`
	AddrType string   `xml:"addrtype,attr"`
}

type Hostnames struct {
	XMLName xml.Name   `xml:"hostnames"`
	Names   []Hostname `xml:"hostname"`
}

type Hostname struct {
	XMLName xml.Name `xml:"hostname"`
	Name    string   `xml:"name,attr"`
}

type HostPorts struct {
	XMLName    xml.Name     `xml:"ports"`
	ExtraPorts ExtraPorts   `xml:"extraports"`
	Ports      []PortDetail `xml:"port"`
}

type ExtraPorts struct {
	XMLName      xml.Name       `xml:"extraports"`
	State        string         `xml:"state,attr"`
	Count        int            `xml:"count,attr"`
	ExtraReasons []ExtraReasons `xml:"extrareasons"`
}

type ExtraReasons struct {
	XMLName xml.Name `xml:"extrareasons"`
	Reason  string   `xml:"reason,attr"`
	Count   int      `xml:"count,attr"`
}

type PortDetail struct {
	XMLName  xml.Name     `xml:"port"`
	Protocol string       `xml:"protocol,attr"`
	PortID   string       `xml:"portid,attr"`
	Script   ScriptOutput `xml:"script"`
}

type ScriptOutput struct {
	XMLName xml.Name      `xml:"script"`
	ID      string        `xml:"id,attr"`
	Elems   []TableElem   `xml:"elem"`
	Tables  []ScriptTable `xml:"table"`
}

type ScriptTable struct {
	XMLName xml.Name      `xml:"table"`
	Key     string        `xml:"key,attr"`
	Elems   []TableElem   `xml:"elem"`
	Tables  []ScriptTable `xml:"table"`
}

type TableElem struct {
	XMLName xml.Name `xml:"elem"`
	Key     string   `xml:"key,attr"`
	Value   string   `xml:",chardata"`
}

type RunStats struct {
	XMLName  xml.Name    `xml:"runstats"`
	Finished RunFinished `xml:"finished"`
}

type RunFinished struct {
	XMLName xml.Name `xml:"finished"`
	Time    string   `xml:"time,attr"`
	Elapsed string   `xml:"elapsed,attr"`
	Summary string   `xml:"summary,attr"`
	Exit    string   `xml:"exit,attr"`
}
