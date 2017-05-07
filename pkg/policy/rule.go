// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"fmt"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

type rule struct {
	api.Rule
}

func (r *rule) String() string {
	return fmt.Sprintf("%v", r.EndpointSelector)
}

func (r *rule) validate() error {
	if r == nil {
		return fmt.Errorf("nil rule")
	}

	if len(r.EndpointSelector) == 0 {
		return fmt.Errorf("empty EndpointSelector")
	}

	return nil
}

func mergeL4Port(r api.PortRule, p api.PortProtocol, proto string, resMap L4PolicyMap) int {
	fmt := fmt.Sprintf("%s:%d", proto, p.Port)
	if _, ok := resMap[fmt]; !ok {
		resMap[fmt] = CreateL4Filter(r, p, proto)
		return 1
	}

	return 0
}

func mergeL4(portRules []api.PortRule, resMap L4PolicyMap) int {
	found := 0

	for _, r := range portRules {
		for _, p := range r.Ports {
			if p.Protocol != "" {
				found += mergeL4Port(r, p, p.Protocol, resMap)
			} else {
				found += mergeL4Port(r, p, "tcp", resMap)
				found += mergeL4Port(r, p, "udp", resMap)
			}
		}
	}

	return found
}

func (r *rule) resolveL4Policy(ctx *SearchContext, result *L4Policy) *L4Policy {
	if !ctx.TargetCoveredBy(r.EndpointSelector) {
		return nil
	}

	found := 0

	for _, r := range r.Ingress {
		found += mergeL4(r.ToPorts, result.Ingress)
	}

	for _, r := range r.Egress {
		found += mergeL4(r.ToPorts, result.Egress)
	}

	if found > 0 {
		return result
	}

	return nil
}

func (r *rule) canReach(ctx *SearchContext) api.Decision {
	if !ctx.TargetCoveredBy(r.EndpointSelector) {
		return api.Undecided
	}

	for _, r := range r.Ingress {
		for _, sel := range r.FromRequires {
			ctx.PolicyTraceVerbose("Rule %s: requires labels %+v\n", r, sel)

			// TODO: get rid of this cast
			if !ctx.From.Contains(labels.LabelArray(sel)) {
				ctx.PolicyTrace("  Required labels not found\n")
				return api.Denied
			}
		}
	}

	// separate loop is needed as failure to meet FromRequires always takes
	// precedence over FromEndpoints
	for _, r := range r.Ingress {
		for _, sel := range r.FromEndpoints {
			ctx.PolicyTraceVerbose("Rule %s: allows labels %+v\n", r, sel)

			// TODO: get rid of this cast
			if ctx.From.Contains(labels.LabelArray(sel)) {
				ctx.PolicyTrace("  Found all required labels\n")
				return api.Allowed
			}

			ctx.PolicyTrace("  Required labels not found\n")
		}
	}

	ctx.PolicyTraceVerbose("rule %s: no FromEndpoints\n", r)

	return api.Undecided
}
