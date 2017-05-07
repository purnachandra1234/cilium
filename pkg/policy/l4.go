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
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/vulcand/route"
)

type AuxRule struct {
	Expr string `json:"expr"`
}

type L4Filter struct {
	// Port is the destination port to allow
	Port int `json:"port,omitempty"`
	// Protocol is the L4 protocol to allow or NONE
	Protocol string `json:"protocol,omitempty"`
	// L7Parser specifies the L7 protocol parser (optional)
	L7Parser string `json:"l7-parser,omitempty"`
	// L7RedirectPort is the L7 proxy port to redirect to (optional)
	L7RedirectPort int `json:"l7-redirect-port,omitempty"`
	// L7Rules is a list of L7 rules which are passed to the L7 proxy (optional)
	L7Rules []AuxRule `json:"l7-rules,omitempty"`
}

func CreateL4Filter(rule api.PortRule, port api.PortProtocol, protocol string) L4Filter {
	l4 := L4Filter{
		Port:           int(port.Port),
		Protocol:       protocol,
		L7RedirectPort: rule.RedirectPort,
	}

	if rule.Rules != nil {
		l7rules := []AuxRule{}
		for _, h := range rule.Rules.HTTP {
			r := AuxRule{}

			if h.Path != "" {
				r.Expr = "Path(\"" + h.Path + "\")"
			}

			if h.Method != "" {
				if r.Expr != "" {
					r.Expr += " && "
				}
				r.Expr += "Method(\"" + h.Method + "\")"
			}

			if r.Expr != "" {
				l7rules = append(l7rules, r)
			}
		}

		if len(l7rules) > 0 {
			l4.L7Rules = l7rules
		}
	}

	return l4
}

// IsRedirect returns true if the L4 filter contains a port redirection
func (l4 *L4Filter) IsRedirect() bool {
	return l4.L7Parser != ""
}

// MarshalIndent returns the `L4Filter` in indented JSON string.
func (l4 *L4Filter) MarshalIndent() string {
	b, err := json.MarshalIndent(l4, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// String returns the `L4Filter` in a human-readable string.
func (l4 L4Filter) String() string {
	b, err := json.Marshal(l4)
	if err != nil {
		return err.Error()
	}
	return string(b)
}

func (l4 *L4Filter) UnmarshalJSON(data []byte) error {
	var l4filter struct {
		Port           int       `json:"port,omitempty"`
		Protocol       string    `json:"protocol,omitempty"`
		L7Parser       string    `json:"l7-parser,omitempty"`
		L7RedirectPort int       `json:"l7-redirect-port,omitempty"`
		L7Rules        []AuxRule `json:"l7-rules,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))

	if err := decoder.Decode(&l4filter); err != nil {
		return fmt.Errorf("decode of L4Filter failed: %s", err)
	}

	if l4filter.Protocol != "" {
		if _, err := u8proto.ParseProtocol(l4filter.Protocol); err != nil {
			return fmt.Errorf("decode of L4Filter failed: %s", err)
		}
	}

	for _, r := range l4filter.L7Rules {
		if !route.IsValid(r.Expr) {
			return fmt.Errorf("invalid filter expression: %s", r.Expr)
		}

		log.Debugf("Valid L7 rule: %s\n", r.Expr)
	}

	l4.Port = l4filter.Port
	l4.Protocol = l4filter.Protocol
	l4.L7Parser = l4filter.L7Parser
	l4.L7RedirectPort = l4filter.L7RedirectPort
	l4.L7Rules = make([]AuxRule, len(l4filter.L7Rules))
	copy(l4.L7Rules, l4filter.L7Rules)

	return nil
}

type L4PolicyMap map[string]L4Filter

// HasRedirect returns true if at least one L4 filter contains a port
// redirection
func (l4 L4PolicyMap) HasRedirect() bool {
	for _, f := range l4 {
		if f.IsRedirect() {
			return true
		}
	}

	return false
}

// containsAllL4 checks if the L4PolicyMap contains all `l4Ports`. Returns false
// if the `L4PolicyMap` has a single rule and l4Ports is empty or if a single
// `l4Port`'s port is not present in the `L4PolicyMap`.
func (l4 L4PolicyMap) containsAllL4(l4Ports []*models.Port) bool {
	if len(l4) == 0 {
		return true
	}
	if len(l4Ports) == 0 {
		return false
	}
	for _, l4CtxIng := range l4Ports {
		lwrProtocol := strings.ToLower(l4CtxIng.Protocol)
		switch lwrProtocol {
		case models.PortProtocolAny:
			tcpPort := fmt.Sprintf("tcp:%d", l4CtxIng.Port)
			_, tcpmatch := l4[tcpPort]
			udpPort := fmt.Sprintf("udp:%d", l4CtxIng.Port)
			_, udpmatch := l4[udpPort]
			if !tcpmatch && !udpmatch {
				return false
			}
		default:
			port := fmt.Sprintf("%s:%d", lwrProtocol, l4CtxIng.Port)
			if _, match := l4[port]; !match {
				return false
			}
		}
	}
	return true
}

type L4Policy struct {
	// key format: "proto:port"
	Ingress L4PolicyMap
	Egress  L4PolicyMap
}

func NewL4Policy() *L4Policy {
	return &L4Policy{
		Ingress: make(L4PolicyMap),
		Egress:  make(L4PolicyMap),
	}
}

// IngressCoversDPorts checks if the receiver's ingress `L4Policy` contains all
// `dPorts`.
func (l4 *L4Policy) IngressCoversDPorts(dPorts []*models.Port) bool {
	return l4.Ingress.containsAllL4(dPorts)
}

// EgressCoversDPorts checks if the receiver's egress `L4Policy` contains all
// `dPorts`.
func (l4 *L4Policy) EgressCoversDPorts(dPorts []*models.Port) bool {
	return l4.Egress.containsAllL4(dPorts)
}

// HasRedirect returns true if the L4 policy contains at least one port redirection
func (l4 *L4Policy) HasRedirect() bool {
	return l4 != nil && (l4.Ingress.HasRedirect() || l4.Egress.HasRedirect())
}

// RequiresConntrack returns true if if the L4 configuration requires
// connection tracking to be enabled.
func (l4 *L4Policy) RequiresConntrack() bool {
	return l4 != nil && (len(l4.Ingress) > 0 || len(l4.Egress) > 0)
}

func (l4 *L4Policy) GetModel() *models.L4Policy {
	if l4 == nil {
		return nil
	}

	ingress := []string{}
	for _, v := range l4.Ingress {
		ingress = append(ingress, v.MarshalIndent())
	}

	egress := []string{}
	for _, v := range l4.Egress {
		egress = append(egress, v.MarshalIndent())
	}

	return &models.L4Policy{
		Ingress: ingress,
		Egress:  egress,
	}
}

func (l4 *L4Policy) DeepCopy() *L4Policy {
	cpy := &L4Policy{
		Ingress: make(map[string]L4Filter, len(l4.Ingress)),
		Egress:  make(map[string]L4Filter, len(l4.Ingress)),
	}

	for k, v := range l4.Ingress {
		cpy.Ingress[k] = v
	}

	for k, v := range l4.Egress {
		cpy.Egress[k] = v
	}

	return cpy
}
