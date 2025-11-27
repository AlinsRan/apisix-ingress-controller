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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/api7/gopkg/pkg/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/wait"

	adctypes "github.com/apache/apisix-ingress-controller/api/adc"
	"github.com/apache/apisix-ingress-controller/test/e2e/framework"
	"github.com/apache/apisix-ingress-controller/test/e2e/scaffold"
)

const gatewayProxyYaml = `
apiVersion: apisix.apache.org/v1alpha1
kind: GatewayProxy
metadata:
  name: apisix-proxy-config
spec:
  provider:
    type: ControlPlane
    controlPlane:
      service:
        name: %s
        port: 9180
      auth:
        type: AdminKey
        adminKey:
          value: "%s"
`

const ingressClassYaml = `
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata:
  name: apisix
spec:
  controller: "%s"
  parameters:
    apiGroup: "apisix.apache.org"
    kind: "GatewayProxy"
    name: "apisix-proxy-config"
    namespace: %s
    scope: "Namespace"
`

var report = &BenchmarkReport{}

var _ = Describe("Benchmark Test", func() {
	var (
		s                = scaffold.NewDefaultScaffold()
		controlAPIClient scaffold.ControlAPIClient
		err              error
		total            = 2000
	)

	ensureNumService := func(number int) error {
		times := 0
		return wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, 10*time.Minute, true, func(ctx context.Context) (done bool, err error) {
			times++
			results, _, err := controlAPIClient.ListServices()
			if err != nil {
				log.Errorw("failed to ListServices", zap.Error(err))
				return false, nil
			}
			if len(results) != number {
				log.Debugw("number of effective services", zap.Int("number", len(results)), zap.Int("times", times))
				return false, nil
			}
			return len(results) == number, nil
		})
	}

	expectUpstream := func(name string, matcher func(upstream adctypes.Upstream) bool) error {
		times := 0
		return wait.PollUntilContextTimeout(context.Background(), 1*time.Second, 10*time.Minute, true, func(ctx context.Context) (done bool, err error) {
			times++
			//upstreams, err := s.Deployer.DefaultDataplaneResource().Upstream().List(context.Background())
			upstreams, _, err := controlAPIClient.ListUpstreams()
			if err != nil {
				log.Errorw("failed to ListServices", zap.Error(err))
				return false, nil
			}
			for _, upstream := range upstreams {
				upsValue := upstream.(map[string]any)
				data, err := json.Marshal(upsValue["value"])
				if err != nil {
					return false, fmt.Errorf("failed to marshal upstream: %v", err)
				}

				var ups adctypes.Upstream
				if err := json.Unmarshal(data, &ups); err != nil {
					return false, fmt.Errorf("failed to unmarshal upstream: %v", err)
				}
				if name != "" && ups.Name != name {
					continue
				}
				if ok := matcher(ups); !ok {
					return false, nil
				}
			}
			return true, nil
		})
	}

	ensureNumUpstreamNodes := func(name string, number int) error {
		return expectUpstream(name, func(upstream adctypes.Upstream) bool {
			if len(upstream.Nodes) != number {
				log.Warnf("expect upstream: [%s] nodes num to be %d, but got %d", upstream.Name, number, len(upstream.Nodes))
				return false
			}
			return true
		})
	}

	BeforeEach(func() {
		By("create GatewayProxy")
		gatewayProxy := fmt.Sprintf(gatewayProxyYaml, framework.ProviderType, s.AdminKey())
		err = s.CreateResourceFromStringWithNamespace(gatewayProxy, s.Namespace())
		Expect(err).NotTo(HaveOccurred(), "creating GatewayProxy")
		time.Sleep(5 * time.Second)

		By("create IngressClass")
		err = s.CreateResourceFromStringWithNamespace(fmt.Sprintf(ingressClassYaml, s.GetControllerName(), s.Namespace()), "")
		Expect(err).NotTo(HaveOccurred(), "creating IngressClass")
		time.Sleep(5 * time.Second)

		By("port-forward to control api service")
		controlAPIClient, err = s.ControlAPIClient()
		Expect(err).NotTo(HaveOccurred(), "create control api client")
	})

	Context("Benchmark ApisixRoute", func() {
		const apisixRouteSpec = `
apiVersion: apisix.apache.org/v2
kind: ApisixRoute
metadata:
  name: %s
spec:
  ingressClassName: apisix
  http:
  - name: rule0
    match:
      paths:
      - /get
      exprs:
      - subject:
          scope: Header
          name: X-Route-Name
        op: Equal
        value: %s
    backends:
    - serviceName: httpbin-service-e2e-test
      servicePort: 80
`
		var apisixRouteSpecHeaders = `
apiVersion: apisix.apache.org/v2
kind: ApisixRoute
metadata:
  name: %s
spec:
  ingressClassName: apisix
  http:
  - name: rule0
    match:
      paths:
      - /headers
      exprs:
      - subject:
          scope: Header
          name: X-Route-Name
        op: Equal
        value: %s
    backends:
    - serviceName: httpbin-service-e2e-test
      servicePort: 80
`

		var apisixUpstreamSpec = `
apiVersion: apisix.apache.org/v2
kind: ApisixUpstream
metadata:
  name: httpbin-service-e2e-test
spec:
  ingressClassName: apisix
  scheme: https
`

		FIt("test 2000 ApisixRoute", func() {
			_ = apisixUpstreamSpec
			By(fmt.Sprintf("prepare %d ApisixRoutes", total))
			err := s.CreateResourceFromString(createBatchApisixRoutes(apisixRouteSpec, total))
			Expect(err).NotTo(HaveOccurred(), "creating ApisixRoutes")

			now := time.Now()
			By(fmt.Sprintf("start cale time for applying %d ApisixRoutes to take effect", total))
			err = ensureNumService(total)
			Expect(err).ShouldNot(HaveOccurred())
			costTime := time.Since(now)
			report.Add("ApisixRoute Benchmark", fmt.Sprintf("Apply %d ApisixRoutes", total), costTime)

			By("Test the time required for an ApisixRoute update to take effect")
			name := getRouteName(10)
			err = s.CreateResourceFromString(fmt.Sprintf(apisixRouteSpecHeaders, name, name))
			Expect(err).NotTo(HaveOccurred())
			now = time.Now()
			Eventually(func() int {
				return s.NewAPISIXClient().GET("/headers").WithHeader("X-Route-Name", name).Expect().Raw().StatusCode
			}).WithTimeout(time.Minute).ProbeEvery(100 * time.Millisecond).Should(Equal(http.StatusOK))
			report.AddResult(TestResult{
				Scenario: "ApisixRoute Benchmark",
				CaseName: fmt.Sprintf("Update a single ApisixRoute base on %d ApisixRoutes", total),
				CostTime: time.Since(now),
			})

			By("Test the time required for a service endpoint change to take effect")
			err = s.ScaleHTTPBIN(2)
			Expect(err).NotTo(HaveOccurred(), "scale httpbin deployment")
			now = time.Now()
			err = ensureNumUpstreamNodes("", 2)
			Expect(err).ShouldNot(HaveOccurred())
			costTime = time.Since(now)
			report.Add("ApisixRoute Benchmark", fmt.Sprintf("Service endpoint change base on %d ApisixRoutes", total), costTime)

			By("Test the time required for an ApisixUpstream update to take effect")
			err = s.CreateResourceFromString(apisixUpstreamSpec)
			Expect(err).NotTo(HaveOccurred(), "creating ApisixUpstream")
			now = time.Now()
			expectUpstream("", func(upstream adctypes.Upstream) bool {
				if upstream.Scheme != "https" {
					log.Warnf("expect upstream: [%s] scheme to be https, but got [%s]", upstream.Name, upstream.Scheme)
					return false
				}
				return true
			})
			costTime = time.Since(now)
			report.Add("ApisixRoute Benchmark", fmt.Sprintf("Update ApisixUpstream base on %d ApisixRoutes", total), costTime)
		})
	})
})

var _ = AfterSuite(func() {
	report.PrintTable()
	// 或 Report.PrintJSON()
	// 或 Report.PrintMarkdown()
})
