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
	"encoding/xml"
	"os"
	"testing"
)

func getSampleOutput(t *testing.T) NMapRun {
	xmlFile, err := os.Open("testdata/nmap-scan.xml")
	if err != nil {
		t.Error(err)
	}
	defer xmlFile.Close()

	dec := xml.NewDecoder(xmlFile)

	var out NMapRun
	if err = dec.Decode(&out); err != nil {
		t.Error(err)
	}

	return out
}

func TestGetCiphers(t *testing.T) {
	ciphers := getSampleOutput(t).GetCiphers("10.96.0.1", "443", "TLSv1.2")

	if len(ciphers) != 5 {
		t.Error("Expected to find 5 ciphers, found", len(ciphers))
	}

	if ciphers[0].Strength != "A" {
		t.Error("Expected first cipher to be grade A, found", ciphers[0].Strength)
	}

	if ciphers[4].Strength != "C" {
		t.Error("Expected last cipher to be grade C, found", ciphers[4].Strength)
	}
}

func TestScannedServices(t *testing.T) {
	svcs, err := getSampleOutput(t).ScannedServices()
	if err != nil {
		t.Error(err)
	}

	if len(svcs) != 100 {
		t.Error("Expected to find 100 services, found", len(svcs))
	}

	for _, p := range []int{21, 22, 23, 1025, 1026, 1027, 1028, 1029, 8080, 8443} {
		if _, ok := svcs[p]; !ok {
			t.Error("Expected to find", p, "in scanned services")
		}
	}
}

func TestGetFlatCiphers(t *testing.T) {
	ciphers := getSampleOutput(t).GetFlatCiphers()

	if len(ciphers) != 5 {
		t.Error("Expected to find 5 ciphers, found", len(ciphers))
	}

	found := false
	for _, c := range ciphers {
		if c.Name == "TLS_RSA_WITH_AES_256_GCM_SHA384" {
			found = true
			if c.HostAddr != "10.96.0.1" {
				t.Errorf("Expected %v to have HostAddr 10.96.0.1, got %v", c.Name, c.HostAddr)
			}
			if c.PortID != "443" {
				t.Errorf("Expected %v to have PortID 443, got %v", c.Name, c.PortID)
			}
			if c.TLSVersion != "TLSv1.2" {
				t.Errorf("Expected %v to have TLSVersion TLSv1.2, got %v", c.Name, c.TLSVersion)
			}
			if c.KexInfo != "rsa 2048" {
				t.Errorf("Expected %v to have KexInfo rsa 2048, got %v", c.Name, c.KexInfo)
			}
			if c.Strength != "A" {
				t.Errorf("Expected %v to have Strength A, got %v", c.Name, c.Strength)
			}
		}
	}
	if !found {
		t.Errorf("No cipher with name TLS_RSA_WITH_AES_256_GCM_SHA384, got ciphers: %v", ciphers)
	}
}
