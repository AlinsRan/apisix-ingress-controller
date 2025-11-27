// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
// // Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package benchmark

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/olekukonko/tablewriter"
)

type TestResult struct {
	Scenario string        `json:"scenario"`
	CaseName string        `json:"case_name"`
	CostTime time.Duration `json:"cost_time"`
}

type BenchmarkReport struct {
	Results []TestResult
}

func (r *BenchmarkReport) PrintTable() {
	table := tablewriter.NewWriter(os.Stdout)
	table.Header([]string{"Scenario", "Case", "Cost"})

	for _, res := range r.Results {
		table.Append([]string{
			res.Scenario,
			res.CaseName,
			res.CostTime.String(),
		})
	}
	table.Render()
}

func (r *BenchmarkReport) PrintJSON() {
	b, _ := json.MarshalIndent(r.Results, "", "  ")
	fmt.Println(string(b))
}

func (r *BenchmarkReport) AddResult(result TestResult) {
	r.Results = append(r.Results, result)
}

func (r *BenchmarkReport) Add(scenario, caseName string, cost time.Duration) {
	r.Results = append(r.Results, TestResult{
		Scenario: scenario,
		CaseName: caseName,
		CostTime: cost,
	})
}

func getRouteName(i int) string {
	return fmt.Sprintf("test-route-%04d", i)
}

func PrintResults(results []TestResult) {
	fmt.Printf("\n======================TEST RESULT ProviderSyncPeriod===============================\n")
	fmt.Printf("%-70s", "Test Case")
	fmt.Printf("%-70s\n", "Time Required")
	fmt.Printf("%-70s\n", "--------------------------------------------------------------------------------------")
	for _, result := range results {
		fmt.Printf("%-70s", result.CaseName)
		fmt.Printf("%-70s\n", result.CostTime)
	}
	fmt.Println("=======================================================================================")
	fmt.Println()
}

func createBatchApisixRoutes(tmpl string, number int) string {
	var buf bytes.Buffer
	for i := 0; i < number; i++ {
		name := getRouteName(i)
		fmt.Fprintf(&buf, tmpl, name, name)
		buf.WriteString("\n---\n")
	}
	return buf.String()
}
