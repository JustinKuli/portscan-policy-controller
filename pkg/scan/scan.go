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

package scan

import (
	"context"
	"encoding/xml"
	"io"
	"os/exec"
	"strconv"
	"strings"

	"github.com/JustinKuli/portscan-policy-controller/pkg/scan/scriptout"
	klog "k8s.io/klog/v2"
)

type SSLEnumRunner struct {
	mainOpts   []string
	outputOpts []string
	portOpts   []string
	ipArgs     []string
}

func SSLEnum(ipAddrs []string) *SSLEnumRunner {
	return &SSLEnumRunner{
		mainOpts:   []string{"-Pn", "--script", "ssl-enum-ciphers"},
		outputOpts: []string{"-oX", "-", "--no-stylesheet"},
		portOpts:   []string{},
		ipArgs:     ipAddrs,
	}
}

func (r *SSLEnumRunner) WithTopNPorts(n int) *SSLEnumRunner {
	r.portOpts = []string{"--top-ports", strconv.Itoa(n)}
	return r
}

func (r *SSLEnumRunner) WithSpecificPorts(ports []int) *SSLEnumRunner {
	strPorts := make([]string, len(ports))
	for i, p := range ports {
		strPorts[i] = strconv.Itoa(p)
	}

	r.portOpts = []string{"-p", strings.Join(strPorts, ",")}
	return r
}

func (r *SSLEnumRunner) WithAllPorts() *SSLEnumRunner {
	r.portOpts = []string{"-p", "-"}
	return r
}

func (r *SSLEnumRunner) Run(ctx context.Context) (scriptout.NMapRun, error) {
	args := append(r.mainOpts, r.outputOpts...)
	args = append(args, r.portOpts...)
	args = append(args, r.ipArgs...)

	klog.V(2).Info("Executing nmap command; args: ", args)
	cmd := exec.CommandContext(ctx, "nmap", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return scriptout.NMapRun{}, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return scriptout.NMapRun{}, err
	}

	if err := cmd.Start(); err != nil {
		return scriptout.NMapRun{}, err
	}

	dec := xml.NewDecoder(stdout)

	var out scriptout.NMapRun
	if err := dec.Decode(&out); err != nil {
		return out, err
	}

	slurp, err := io.ReadAll(stderr)
	if err != nil {
		return out, err
	}
	klog.V(2).Info("nmap stderr output: ", string(slurp))

	if err := cmd.Wait(); err != nil {
		return out, err
	}

	return out, nil
}
