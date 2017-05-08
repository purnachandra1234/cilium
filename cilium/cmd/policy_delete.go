// Copyright 2017 Authors of Cilium
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

package cmd

import (
	"github.com/spf13/cobra"
)

// policyDeleteCmd represents the policy_delete command
var policyDeleteCmd = &cobra.Command{
	Use:   "delete [<labels>]",
	Short: "Delete policy rules",
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.PolicyDelete(); err != nil {
			Fatalf("Cannot delete policy: %s\n", err)
		}
	},
}

func init() {
	policyCmd.AddCommand(policyDeleteCmd)
}
