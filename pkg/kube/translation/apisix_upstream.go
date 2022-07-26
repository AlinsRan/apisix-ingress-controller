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
	"fmt"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/apache/apisix-ingress-controller/pkg/id"
	configv2 "github.com/apache/apisix-ingress-controller/pkg/kube/apisix/apis/config/v2"
	configv2beta3 "github.com/apache/apisix-ingress-controller/pkg/kube/apisix/apis/config/v2beta3"
	"github.com/apache/apisix-ingress-controller/pkg/log"
	"github.com/apache/apisix-ingress-controller/pkg/types"
	apisixv1 "github.com/apache/apisix-ingress-controller/pkg/types/apisix/v1"
)

const (
	ResolveGranularityService  = "service"
	ResolveGranularityEndpoint = "endpoint"
)

type UpstreamArg struct {
	Namespace          string
	Name               string
	Port               intstr.IntOrString
	ServicePort        *corev1.ServicePort
	ResolveGranularity string
	Subset             string
	Labels             types.Labels
}

func (t *translator) translateUpstreamV2(arg *UpstreamArg) (*apisixv1.Upstream, error) {
	ups := apisixv1.NewDefaultUpstream()
	ups.Name = apisixv1.ComposeUpstreamName(arg.Namespace, arg.Name, arg.Subset, arg.Port.IntVal)
	ups.ID = id.GenID(ups.Name)
	au, err := t.ApisixUpstreamLister.V2(arg.Namespace, ups.Name)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			// If subset in ApisixRoute is not empty but the ApisixUpstream resource not found,
			// just set an empty node list.
			if arg.Subset != "" {
				ups.Nodes = apisixv1.UpstreamNodes{}
				return ups, nil
			}
		} else {
			return nil, &translateError{
				field:  "ApisixUpstream",
				reason: err.Error(),
			}
		}
	}
	if arg.Subset != "" {
		for _, ss := range au.V2().Spec.Subsets {
			if ss.Name == arg.Subset {
				arg.Labels = ss.Labels
				break
			}
		}
	}
	// Filter nodes by subset.
	nodes, err := t.TranslateUpstreamNodes(arg)
	if err != nil {
		return nil, err
	}
	if au == nil || au.V2().Spec == nil {
		ups.Nodes = nodes
		return ups, nil
	}

	upsCfg := &au.V2().Spec.ApisixUpstreamConfig
	for _, pls := range au.V2().Spec.PortLevelSettings {
		if pls.Port == arg.Port.IntVal {
			upsCfg = &pls.ApisixUpstreamConfig
			break
		}
	}
	ups, err = t.TranslateUpstreamConfigV2(upsCfg)
	if err != nil {
		return nil, err
	}
	ups.Nodes = nodes
	return ups, nil
}

func (t *translator) translateUpstreamV2beta3(arg *UpstreamArg) (*apisixv1.Upstream, error) {
	ups := apisixv1.NewDefaultUpstream()
	ups.Name = apisixv1.ComposeUpstreamName(arg.Namespace, arg.Name, arg.Subset, arg.Port.IntVal)
	ups.ID = id.GenID(ups.Name)
	au, err := t.ApisixUpstreamLister.V2(arg.Namespace, ups.Name)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			// If subset in ApisixRoute is not empty but the ApisixUpstream resource not found,
			// just set an empty node list.
			if arg.Subset != "" {
				ups.Nodes = apisixv1.UpstreamNodes{}
				return ups, nil
			}
		} else {
			return nil, &translateError{
				field:  "ApisixUpstream",
				reason: err.Error(),
			}
		}
	}
	// Filter nodes by subset.
	nodes, err := t.TranslateUpstreamNodes(arg)
	if err != nil {
		return nil, err
	}
	if au == nil || au.V2beta3().Spec == nil {
		ups.Nodes = nodes
		return ups, nil
	}

	upsCfg := &au.V2beta3().Spec.ApisixUpstreamConfig
	for _, pls := range au.V2beta3().Spec.PortLevelSettings {
		if pls.Port == arg.Port.IntVal {
			upsCfg = &pls.ApisixUpstreamConfig
			break
		}
	}
	ups, err = t.TranslateUpstreamConfigV2beta3(upsCfg)
	if err != nil {
		return nil, err
	}
	ups.Nodes = nodes
	return ups, nil
}

func (t *translator) TranslateUpstreamNodes(arg *UpstreamArg) (apisixv1.UpstreamNodes, error) {
	svc, err := t.ServiceLister.Services(arg.Namespace).Get(arg.Name)
	if err != nil {
		return nil, &translateError{
			field:  "service",
			reason: err.Error(),
		}
	}
	var svcPort *corev1.ServicePort
	if arg.Port.Type == intstr.String {
		for _, exposePort := range svc.Spec.Ports {
			if exposePort.Name == arg.Port.StrVal {
				svcPort = &exposePort
				break
			}
		}
	} else {
		for _, exposePort := range svc.Spec.Ports {
			if exposePort.Port == arg.Port.IntVal {
				svcPort = &exposePort
				break
			}
		}
	}
	if svcPort == nil {
		return nil, &translateError{
			field:  "service",
			reason: "port not found",
		}
	}
	if arg.ResolveGranularity == "" {
		arg.ResolveGranularity = ResolveGranularityEndpoint
	}
	switch arg.ResolveGranularity {
	case ResolveGranularityService:
		if svc.Spec.ClusterIP == "" {
			return nil, errors.New("conflict headless service and backend resolve granularity")
		}
		return apisixv1.UpstreamNodes{
			{
				Host:   svc.Spec.ClusterIP,
				Port:   int(svcPort.Port),
				Weight: _defaultWeight,
			},
		}, nil
	case ResolveGranularityEndpoint:
		nodes := make(apisixv1.UpstreamNodes, 0)
		endpoint, err := t.EndpointLister.GetEndpoint(arg.Namespace, arg.Name)
		if err != nil {
			return nodes, nil
		}

		namespace, err := endpoint.Namespace()
		if err != nil {
			log.Errorw("failed to get endpoint namespace",
				zap.Error(err),
				zap.Any("endpoint", endpoint),
			)
			return nil, err
		}

		// As nodes is not optional, here we create an empty slice,
		// not a nil slice.
		for _, hostport := range endpoint.Endpoints(svcPort) {
			nodes = append(nodes, apisixv1.UpstreamNode{
				Host: hostport.Host,
				Port: hostport.Port,
				// FIXME Custom node weight
				Weight: _defaultWeight,
			})
		}
		if arg.Labels != nil {
			nodes = t.filterNodesByLabels(nodes, arg.Labels, namespace)
			return nodes, nil
		}
		return nodes, nil
	}
	return nil, fmt.Errorf("%s not supported", arg.ResolveGranularity)
}

func (t *translator) translateUpstreamRetriesAndTimeoutV2beta3(retries *int, timeout *configv2beta3.UpstreamTimeout, ups *apisixv1.Upstream) error {
	if retries != nil && *retries < 0 {
		return &translateError{
			field:  "retries",
			reason: "invalid value",
		}
	}
	ups.Retries = retries
	if timeout == nil {
		return nil
	}

	// Since the schema of timeout doesn't allow only configuring
	// one or two items. Here we assign the default value first.
	connTimeout := apisixv1.DefaultUpstreamTimeout
	readTimeout := apisixv1.DefaultUpstreamTimeout
	sendTimeout := apisixv1.DefaultUpstreamTimeout
	if timeout.Connect.Duration < 0 {
		return &translateError{
			field:  "timeout.connect",
			reason: "invalid value",
		}
	} else if timeout.Connect.Duration > 0 {
		connTimeout = int(timeout.Connect.Seconds())
	}
	if timeout.Read.Duration < 0 {
		return &translateError{
			field:  "timeout.read",
			reason: "invalid value",
		}
	} else if timeout.Read.Duration > 0 {
		readTimeout = int(timeout.Read.Seconds())
	}
	if timeout.Send.Duration < 0 {
		return &translateError{
			field:  "timeout.send",
			reason: "invalid value",
		}
	} else if timeout.Send.Duration > 0 {
		sendTimeout = int(timeout.Send.Seconds())
	}
	ups.Timeout = &apisixv1.UpstreamTimeout{
		Connect: connTimeout,
		Send:    sendTimeout,
		Read:    readTimeout,
	}
	return nil
}

func (t *translator) translateUpstreamScheme(scheme string, ups *apisixv1.Upstream) error {
	if scheme == "" {
		ups.Scheme = apisixv1.SchemeHTTP
		return nil
	}
	switch scheme {
	case apisixv1.SchemeHTTP, apisixv1.SchemeGRPC, apisixv1.SchemeHTTPS, apisixv1.SchemeGRPCS:
		ups.Scheme = scheme
		return nil
	default:
		return &translateError{field: "scheme", reason: "invalid value"}
	}
}

func (t *translator) translateUpstreamLoadBalancerV2beta3(lb *configv2beta3.LoadBalancer, ups *apisixv1.Upstream) error {
	if lb == nil || lb.Type == "" {
		ups.Type = apisixv1.LbRoundRobin
		return nil
	}
	switch lb.Type {
	case apisixv1.LbRoundRobin, apisixv1.LbLeastConn, apisixv1.LbEwma:
		ups.Type = lb.Type
	case apisixv1.LbConsistentHash:
		ups.Type = lb.Type
		ups.Key = lb.Key
		switch lb.HashOn {
		case apisixv1.HashOnVars:
			fallthrough
		case apisixv1.HashOnHeader:
			fallthrough
		case apisixv1.HashOnCookie:
			fallthrough
		case apisixv1.HashOnConsumer:
			fallthrough
		case apisixv1.HashOnVarsCombination:
			ups.HashOn = lb.HashOn
		default:
			return &translateError{field: "loadbalancer.hashOn", reason: "invalid value"}
		}
	default:
		return &translateError{
			field:  "loadbalancer.type",
			reason: "invalid value",
		}
	}
	return nil
}

func (t *translator) translateUpstreamHealthCheckV2beta3(config *configv2beta3.HealthCheck, ups *apisixv1.Upstream) error {
	if config == nil || (config.Passive == nil && config.Active == nil) {
		return nil
	}
	var hc apisixv1.UpstreamHealthCheck
	if config.Passive != nil {
		passive, err := t.translateUpstreamPassiveHealthCheckV2beta3(config.Passive)
		if err != nil {
			return err
		}
		hc.Passive = passive
	}

	if config.Active != nil {
		active, err := t.translateUpstreamActiveHealthCheckV2beta3(config.Active)
		if err != nil {
			return err
		}
		hc.Active = active
	} else {
		return &translateError{
			field:  "healthCheck.active",
			reason: "not exist",
		}
	}

	ups.Checks = &hc
	return nil
}

func (t translator) translateClientTLSV2beta3(config *configv2beta3.ApisixSecret, ups *apisixv1.Upstream) error {
	if config == nil {
		return nil
	}
	s, err := t.SecretLister.Secrets(config.Namespace).Get(config.Name)
	if err != nil {
		return &translateError{
			field:  "tlsSecret",
			reason: fmt.Sprintf("get secret failed, %v", err),
		}
	}
	cert, key, err := t.ExtractKeyPair(s, true)
	if err != nil {
		return &translateError{
			field:  "tlsSecret",
			reason: fmt.Sprintf("extract cert and key from secret failed, %v", err),
		}
	}
	ups.TLS = &apisixv1.ClientTLS{
		Cert: string(cert),
		Key:  string(key),
	}
	return nil
}

func (t *translator) translateUpstreamActiveHealthCheckV2beta3(config *configv2beta3.ActiveHealthCheck) (*apisixv1.UpstreamActiveHealthCheck, error) {
	var active apisixv1.UpstreamActiveHealthCheck
	switch config.Type {
	case apisixv1.HealthCheckHTTP, apisixv1.HealthCheckHTTPS, apisixv1.HealthCheckTCP:
		active.Type = config.Type
	case "":
		active.Type = apisixv1.HealthCheckHTTP
	default:
		return nil, &translateError{
			field:  "healthCheck.active.Type",
			reason: "invalid value",
		}
	}

	active.Timeout = int(config.Timeout.Seconds())
	if config.Port < 0 || config.Port > 65535 {
		return nil, &translateError{
			field:  "healthCheck.active.port",
			reason: "invalid value",
		}
	} else {
		active.Port = config.Port
	}
	if config.Concurrency < 0 {
		return nil, &translateError{
			field:  "healthCheck.active.concurrency",
			reason: "invalid value",
		}
	} else {
		active.Concurrency = config.Concurrency
	}
	active.Host = config.Host
	active.HTTPPath = config.HTTPPath
	active.HTTPRequestHeaders = config.RequestHeaders

	if config.StrictTLS == nil || *config.StrictTLS {
		active.HTTPSVerifyCert = true
	}

	if config.Healthy != nil {
		if config.Healthy.Successes < 0 || config.Healthy.Successes > apisixv1.HealthCheckMaxConsecutiveNumber {
			return nil, &translateError{
				field:  "healthCheck.active.healthy.successes",
				reason: "invalid value",
			}
		}
		active.Healthy.Successes = config.Healthy.Successes
		if config.Healthy.HTTPCodes != nil && len(config.Healthy.HTTPCodes) < 1 {
			return nil, &translateError{
				field:  "healthCheck.active.healthy.httpCodes",
				reason: "empty",
			}
		}
		active.Healthy.HTTPStatuses = config.Healthy.HTTPCodes

		if config.Healthy.Interval.Duration < apisixv1.ActiveHealthCheckMinInterval {
			return nil, &translateError{
				field:  "healthCheck.active.healthy.interval",
				reason: "invalid value",
			}
		}
		active.Healthy.Interval = int(config.Healthy.Interval.Seconds())
	}

	if config.Unhealthy != nil {
		if config.Unhealthy.HTTPFailures < 0 || config.Unhealthy.HTTPFailures > apisixv1.HealthCheckMaxConsecutiveNumber {
			return nil, &translateError{
				field:  "healthCheck.active.unhealthy.httpFailures",
				reason: "invalid value",
			}
		}
		active.Unhealthy.HTTPFailures = config.Unhealthy.HTTPFailures

		if config.Unhealthy.TCPFailures < 0 || config.Unhealthy.TCPFailures > apisixv1.HealthCheckMaxConsecutiveNumber {
			return nil, &translateError{
				field:  "healthCheck.active.unhealthy.tcpFailures",
				reason: "invalid value",
			}
		}
		active.Unhealthy.TCPFailures = config.Unhealthy.TCPFailures
		active.Unhealthy.Timeouts = config.Unhealthy.Timeouts

		if config.Unhealthy.HTTPCodes != nil && len(config.Unhealthy.HTTPCodes) < 1 {
			return nil, &translateError{
				field:  "healthCheck.active.unhealthy.httpCodes",
				reason: "empty",
			}
		}
		active.Unhealthy.HTTPStatuses = config.Unhealthy.HTTPCodes

		if config.Unhealthy.Interval.Duration < apisixv1.ActiveHealthCheckMinInterval {
			return nil, &translateError{
				field:  "healthCheck.active.unhealthy.interval",
				reason: "invalid value",
			}
		}
		active.Unhealthy.Interval = int(config.Unhealthy.Interval.Seconds())
	}

	return &active, nil
}

func (t *translator) translateUpstreamPassiveHealthCheckV2beta3(config *configv2beta3.PassiveHealthCheck) (*apisixv1.UpstreamPassiveHealthCheck, error) {
	var passive apisixv1.UpstreamPassiveHealthCheck
	switch config.Type {
	case apisixv1.HealthCheckHTTP, apisixv1.HealthCheckHTTPS, apisixv1.HealthCheckTCP:
		passive.Type = config.Type
	case "":
		passive.Type = apisixv1.HealthCheckHTTP
	default:
		return nil, &translateError{
			field:  "healthCheck.passive.Type",
			reason: "invalid value",
		}
	}
	if config.Healthy != nil {
		// zero means use the default value.
		if config.Healthy.Successes < 0 || config.Healthy.Successes > apisixv1.HealthCheckMaxConsecutiveNumber {
			return nil, &translateError{
				field:  "healthCheck.passive.healthy.successes",
				reason: "invalid value",
			}
		}
		passive.Healthy.Successes = config.Healthy.Successes
		if config.Healthy.HTTPCodes != nil && len(config.Healthy.HTTPCodes) < 1 {
			return nil, &translateError{
				field:  "healthCheck.passive.healthy.httpCodes",
				reason: "empty",
			}
		}
		passive.Healthy.HTTPStatuses = config.Healthy.HTTPCodes
	}

	if config.Unhealthy != nil {
		if config.Unhealthy.HTTPFailures < 0 || config.Unhealthy.HTTPFailures > apisixv1.HealthCheckMaxConsecutiveNumber {
			return nil, &translateError{
				field:  "healthCheck.passive.unhealthy.httpFailures",
				reason: "invalid value",
			}
		}
		passive.Unhealthy.HTTPFailures = config.Unhealthy.HTTPFailures

		if config.Unhealthy.TCPFailures < 0 || config.Unhealthy.TCPFailures > apisixv1.HealthCheckMaxConsecutiveNumber {
			return nil, &translateError{
				field:  "healthCheck.passive.unhealthy.tcpFailures",
				reason: "invalid value",
			}
		}
		passive.Unhealthy.TCPFailures = config.Unhealthy.TCPFailures
		passive.Unhealthy.Timeouts = config.Unhealthy.Timeouts

		if config.Unhealthy.HTTPCodes != nil && len(config.Unhealthy.HTTPCodes) < 1 {
			return nil, &translateError{
				field:  "healthCheck.passive.unhealthy.httpCodes",
				reason: "empty",
			}
		}
		passive.Unhealthy.HTTPStatuses = config.Unhealthy.HTTPCodes
	}
	return &passive, nil
}

func (t *translator) translateUpstreamRetriesAndTimeoutV2(retries *int, timeout *configv2.UpstreamTimeout, ups *apisixv1.Upstream) error {
	if retries != nil && *retries < 0 {
		return &translateError{
			field:  "retries",
			reason: "invalid value",
		}
	}
	ups.Retries = retries
	if timeout == nil {
		return nil
	}

	// Since the schema of timeout doesn't allow only configuring
	// one or two items. Here we assign the default value first.
	connTimeout := apisixv1.DefaultUpstreamTimeout
	readTimeout := apisixv1.DefaultUpstreamTimeout
	sendTimeout := apisixv1.DefaultUpstreamTimeout
	if timeout.Connect.Duration < 0 {
		return &translateError{
			field:  "timeout.connect",
			reason: "invalid value",
		}
	} else if timeout.Connect.Duration > 0 {
		connTimeout = int(timeout.Connect.Seconds())
	}
	if timeout.Read.Duration < 0 {
		return &translateError{
			field:  "timeout.read",
			reason: "invalid value",
		}
	} else if timeout.Read.Duration > 0 {
		readTimeout = int(timeout.Read.Seconds())
	}
	if timeout.Send.Duration < 0 {
		return &translateError{
			field:  "timeout.send",
			reason: "invalid value",
		}
	} else if timeout.Send.Duration > 0 {
		sendTimeout = int(timeout.Send.Seconds())
	}
	ups.Timeout = &apisixv1.UpstreamTimeout{
		Connect: connTimeout,
		Send:    sendTimeout,
		Read:    readTimeout,
	}
	return nil
}

func (t *translator) translateUpstreamLoadBalancerV2(lb *configv2.LoadBalancer, ups *apisixv1.Upstream) error {
	if lb == nil || lb.Type == "" {
		ups.Type = apisixv1.LbRoundRobin
		return nil
	}
	switch lb.Type {
	case apisixv1.LbRoundRobin, apisixv1.LbLeastConn, apisixv1.LbEwma:
		ups.Type = lb.Type
	case apisixv1.LbConsistentHash:
		ups.Type = lb.Type
		ups.Key = lb.Key
		switch lb.HashOn {
		case apisixv1.HashOnVars:
			fallthrough
		case apisixv1.HashOnHeader:
			fallthrough
		case apisixv1.HashOnCookie:
			fallthrough
		case apisixv1.HashOnConsumer:
			fallthrough
		case apisixv1.HashOnVarsCombination:
			ups.HashOn = lb.HashOn
		default:
			return &translateError{field: "loadbalancer.hashOn", reason: "invalid value"}
		}
	default:
		return &translateError{
			field:  "loadbalancer.type",
			reason: "invalid value",
		}
	}
	return nil
}

func (t *translator) translateUpstreamHealthCheckV2(config *configv2.HealthCheck, ups *apisixv1.Upstream) error {
	if config == nil || (config.Passive == nil && config.Active == nil) {
		return nil
	}
	var hc apisixv1.UpstreamHealthCheck
	if config.Passive != nil {
		passive, err := t.translateUpstreamPassiveHealthCheckV2(config.Passive)
		if err != nil {
			return err
		}
		hc.Passive = passive
	}

	if config.Active != nil {
		active, err := t.translateUpstreamActiveHealthCheckV2(config.Active)
		if err != nil {
			return err
		}
		hc.Active = active
	} else {
		return &translateError{
			field:  "healthCheck.active",
			reason: "not exist",
		}
	}

	ups.Checks = &hc
	return nil
}

func (t translator) translateClientTLSV2(config *configv2.ApisixSecret, ups *apisixv1.Upstream) error {
	if config == nil {
		return nil
	}
	s, err := t.SecretLister.Secrets(config.Namespace).Get(config.Name)
	if err != nil {
		return &translateError{
			field:  "tlsSecret",
			reason: fmt.Sprintf("get secret failed, %v", err),
		}
	}
	cert, key, err := t.ExtractKeyPair(s, true)
	if err != nil {
		return &translateError{
			field:  "tlsSecret",
			reason: fmt.Sprintf("extract cert and key from secret failed, %v", err),
		}
	}
	ups.TLS = &apisixv1.ClientTLS{
		Cert: string(cert),
		Key:  string(key),
	}
	return nil
}

func (t *translator) translateUpstreamActiveHealthCheckV2(config *configv2.ActiveHealthCheck) (*apisixv1.UpstreamActiveHealthCheck, error) {
	var active apisixv1.UpstreamActiveHealthCheck
	switch config.Type {
	case apisixv1.HealthCheckHTTP, apisixv1.HealthCheckHTTPS, apisixv1.HealthCheckTCP:
		active.Type = config.Type
	case "":
		active.Type = apisixv1.HealthCheckHTTP
	default:
		return nil, &translateError{
			field:  "healthCheck.active.Type",
			reason: "invalid value",
		}
	}

	active.Timeout = int(config.Timeout.Seconds())
	if config.Port < 0 || config.Port > 65535 {
		return nil, &translateError{
			field:  "healthCheck.active.port",
			reason: "invalid value",
		}
	} else {
		active.Port = config.Port
	}
	if config.Concurrency < 0 {
		return nil, &translateError{
			field:  "healthCheck.active.concurrency",
			reason: "invalid value",
		}
	} else {
		active.Concurrency = config.Concurrency
	}
	active.Host = config.Host
	active.HTTPPath = config.HTTPPath
	active.HTTPRequestHeaders = config.RequestHeaders

	if config.StrictTLS == nil || *config.StrictTLS {
		active.HTTPSVerifyCert = true
	}

	if config.Healthy != nil {
		if config.Healthy.Successes < 0 || config.Healthy.Successes > apisixv1.HealthCheckMaxConsecutiveNumber {
			return nil, &translateError{
				field:  "healthCheck.active.healthy.successes",
				reason: "invalid value",
			}
		}
		active.Healthy.Successes = config.Healthy.Successes
		if config.Healthy.HTTPCodes != nil && len(config.Healthy.HTTPCodes) < 1 {
			return nil, &translateError{
				field:  "healthCheck.active.healthy.httpCodes",
				reason: "empty",
			}
		}
		active.Healthy.HTTPStatuses = config.Healthy.HTTPCodes

		if config.Healthy.Interval.Duration < apisixv1.ActiveHealthCheckMinInterval {
			return nil, &translateError{
				field:  "healthCheck.active.healthy.interval",
				reason: "invalid value",
			}
		}
		active.Healthy.Interval = int(config.Healthy.Interval.Seconds())
	}

	if config.Unhealthy != nil {
		if config.Unhealthy.HTTPFailures < 0 || config.Unhealthy.HTTPFailures > apisixv1.HealthCheckMaxConsecutiveNumber {
			return nil, &translateError{
				field:  "healthCheck.active.unhealthy.httpFailures",
				reason: "invalid value",
			}
		}
		active.Unhealthy.HTTPFailures = config.Unhealthy.HTTPFailures

		if config.Unhealthy.TCPFailures < 0 || config.Unhealthy.TCPFailures > apisixv1.HealthCheckMaxConsecutiveNumber {
			return nil, &translateError{
				field:  "healthCheck.active.unhealthy.tcpFailures",
				reason: "invalid value",
			}
		}
		active.Unhealthy.TCPFailures = config.Unhealthy.TCPFailures
		active.Unhealthy.Timeouts = config.Unhealthy.Timeouts

		if config.Unhealthy.HTTPCodes != nil && len(config.Unhealthy.HTTPCodes) < 1 {
			return nil, &translateError{
				field:  "healthCheck.active.unhealthy.httpCodes",
				reason: "empty",
			}
		}
		active.Unhealthy.HTTPStatuses = config.Unhealthy.HTTPCodes

		if config.Unhealthy.Interval.Duration < apisixv1.ActiveHealthCheckMinInterval {
			return nil, &translateError{
				field:  "healthCheck.active.unhealthy.interval",
				reason: "invalid value",
			}
		}
		active.Unhealthy.Interval = int(config.Unhealthy.Interval.Seconds())
	}

	return &active, nil
}

func (t *translator) translateUpstreamPassiveHealthCheckV2(config *configv2.PassiveHealthCheck) (*apisixv1.UpstreamPassiveHealthCheck, error) {
	var passive apisixv1.UpstreamPassiveHealthCheck
	switch config.Type {
	case apisixv1.HealthCheckHTTP, apisixv1.HealthCheckHTTPS, apisixv1.HealthCheckTCP:
		passive.Type = config.Type
	case "":
		passive.Type = apisixv1.HealthCheckHTTP
	default:
		return nil, &translateError{
			field:  "healthCheck.passive.Type",
			reason: "invalid value",
		}
	}
	if config.Healthy != nil {
		// zero means use the default value.
		if config.Healthy.Successes < 0 || config.Healthy.Successes > apisixv1.HealthCheckMaxConsecutiveNumber {
			return nil, &translateError{
				field:  "healthCheck.passive.healthy.successes",
				reason: "invalid value",
			}
		}
		passive.Healthy.Successes = config.Healthy.Successes
		if config.Healthy.HTTPCodes != nil && len(config.Healthy.HTTPCodes) < 1 {
			return nil, &translateError{
				field:  "healthCheck.passive.healthy.httpCodes",
				reason: "empty",
			}
		}
		passive.Healthy.HTTPStatuses = config.Healthy.HTTPCodes
	}

	if config.Unhealthy != nil {
		if config.Unhealthy.HTTPFailures < 0 || config.Unhealthy.HTTPFailures > apisixv1.HealthCheckMaxConsecutiveNumber {
			return nil, &translateError{
				field:  "healthCheck.passive.unhealthy.httpFailures",
				reason: "invalid value",
			}
		}
		passive.Unhealthy.HTTPFailures = config.Unhealthy.HTTPFailures

		if config.Unhealthy.TCPFailures < 0 || config.Unhealthy.TCPFailures > apisixv1.HealthCheckMaxConsecutiveNumber {
			return nil, &translateError{
				field:  "healthCheck.passive.unhealthy.tcpFailures",
				reason: "invalid value",
			}
		}
		passive.Unhealthy.TCPFailures = config.Unhealthy.TCPFailures
		passive.Unhealthy.Timeouts = config.Unhealthy.Timeouts

		if config.Unhealthy.HTTPCodes != nil && len(config.Unhealthy.HTTPCodes) < 1 {
			return nil, &translateError{
				field:  "healthCheck.passive.unhealthy.httpCodes",
				reason: "empty",
			}
		}
		passive.Unhealthy.HTTPStatuses = config.Unhealthy.HTTPCodes
	}
	return &passive, nil
}
