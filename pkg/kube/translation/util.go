// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package translation

import (
	"errors"
	"net"

	"go.uber.org/zap"

	"github.com/apache/apisix-ingress-controller/pkg/id"
	"github.com/apache/apisix-ingress-controller/pkg/log"
	"github.com/apache/apisix-ingress-controller/pkg/types"
	apisixv1 "github.com/apache/apisix-ingress-controller/pkg/types/apisix/v1"
)

var (
	_errInvalidAddress = errors.New("address is neither IP or CIDR")
)

// translateUpstreamNotStrictly translates Upstream nodes with a loose way, only generate ID and Name for delete Event.
func (t *translator) translateUpstreamNotStrictly(namespace, svcName, subset string, svcPort int32) (*apisixv1.Upstream, error) {
	ups := &apisixv1.Upstream{}
	ups.Name = apisixv1.ComposeUpstreamName(namespace, svcName, subset, svcPort)
	ups.ID = id.GenID(ups.Name)
	return ups, nil
}

func (t *translator) filterNodesByLabels(nodes apisixv1.UpstreamNodes, labels types.Labels, namespace string) apisixv1.UpstreamNodes {
	if labels == nil {
		return nodes
	}

	filteredNodes := make(apisixv1.UpstreamNodes, 0)
	for _, node := range nodes {
		podName, err := t.PodCache.GetNameByIP(node.Host)
		if err != nil {
			log.Errorw("failed to find pod name by ip, ignore it",
				zap.Error(err),
				zap.String("pod_ip", node.Host),
			)
			continue
		}
		pod, err := t.PodLister.Pods(namespace).Get(podName)
		if err != nil {
			log.Errorw("failed to find pod, ignore it",
				zap.Error(err),
				zap.String("pod_name", podName),
			)
			continue
		}
		if labels.IsSubsetOf(pod.Labels) {
			filteredNodes = append(filteredNodes, node)
		}
	}
	return filteredNodes
}

func validateRemoteAddrs(remoteAddrs []string) error {
	for _, addr := range remoteAddrs {
		if ip := net.ParseIP(addr); ip == nil {
			// addr is not an IP address, try to parse it as a CIDR.
			if _, _, err := net.ParseCIDR(addr); err != nil {
				return _errInvalidAddress
			}
		}
	}
	return nil
}
