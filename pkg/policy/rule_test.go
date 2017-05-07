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
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
)

func (ds *PolicyTestSuite) TestRuleCanReach(c *C) {
	fooFoo2ToBar := &SearchContext{
		From: labels.ParseLabelArray("foo", "foo2"),
		To:   labels.ParseLabelArray("bar"),
	}
	fooToBar := &SearchContext{
		From: labels.ParseLabelArray("foo"),
		To:   labels.ParseLabelArray("bar"),
	}

	rule1 := rule{
		api.Rule{
			EndpointSelector: api.EndpointSelector{labels.ParseLabel("bar")},
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.ParseEndpointSelector("foo", "foo2"),
					},
				},
			},
		},
	}

	c.Assert(rule1.canReach(fooFoo2ToBar), Equals, api.Allowed)
	c.Assert(rule1.canReach(fooToBar), Equals, api.Undecided)

	// selector: bar
	// allow: foo
	// require: baz
	rule2 := rule{
		api.Rule{
			EndpointSelector: api.EndpointSelector{labels.ParseLabel("bar")},
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.ParseEndpointSelector("foo"),
					},
					FromRequires: []api.EndpointSelector{
						api.ParseEndpointSelector("baz"),
					},
				},
			},
		},
	}

	fooBazToBar := &SearchContext{
		From: labels.ParseLabelArray("foo", "baz"),
		To:   labels.ParseLabelArray("bar"),
	}
	bazToBar := &SearchContext{
		From: labels.ParseLabelArray("baz"),
		To:   labels.ParseLabelArray("bar"),
	}

	c.Assert(rule2.canReach(fooToBar), Equals, api.Denied)
	c.Assert(rule2.canReach(bazToBar), Equals, api.Undecided)
	c.Assert(rule2.canReach(fooBazToBar), Equals, api.Allowed)

}

func (ds *PolicyTestSuite) TestL4Policy(c *C) {
	toBar := &SearchContext{To: labels.ParseLabelArray("bar")}
	toFoo := &SearchContext{To: labels.ParseLabelArray("foo")}

	rule1 := &rule{
		api.Rule{
			EndpointSelector: api.EndpointSelector{labels.ParseLabel("bar")},
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: 80, Protocol: "tcp"},
							{Port: 8080, Protocol: "tcp"},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
			},
			Egress: []api.EgressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: 3000},
						},
					}},
				},
			},
		},
	}

	l7rules := []AuxRule{
		{Expr: "Path(\"/\") && Method(\"GET\")"},
	}

	expected := NewL4Policy()
	expected.Ingress["tcp:80"] = L4Filter{Port: 80, Protocol: "tcp", L7Rules: l7rules}
	expected.Ingress["tcp:8080"] = L4Filter{Port: 8080, Protocol: "tcp", L7Rules: l7rules}
	expected.Egress["tcp:3000"] = L4Filter{Port: 3000, Protocol: "tcp"}
	expected.Egress["udp:3000"] = L4Filter{Port: 3000, Protocol: "udp"}

	c.Assert(*rule1.resolveL4Policy(toBar, NewL4Policy()), DeepEquals, *expected)
	c.Assert(rule1.resolveL4Policy(toFoo, NewL4Policy()), IsNil)
}
