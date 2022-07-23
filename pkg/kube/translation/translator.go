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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	listerscorev1 "k8s.io/client-go/listers/core/v1"

	config "github.com/apache/apisix-ingress-controller/pkg/config"
	"github.com/apache/apisix-ingress-controller/pkg/kube"
	configv2 "github.com/apache/apisix-ingress-controller/pkg/kube/apisix/apis/config/v2"
	configv2beta2 "github.com/apache/apisix-ingress-controller/pkg/kube/apisix/apis/config/v2beta2"
	configv2beta3 "github.com/apache/apisix-ingress-controller/pkg/kube/apisix/apis/config/v2beta3"
	"github.com/apache/apisix-ingress-controller/pkg/types"
	apisixv1 "github.com/apache/apisix-ingress-controller/pkg/types/apisix/v1"
)

const (
	_defaultWeight = 100
)

type translateError struct {
	field  string
	reason string
}

func (te *translateError) Error() string {
	return fmt.Sprintf("%s: %s", te.field, te.reason)
}

// Translator translates Apisix* CRD resources to the description in APISIX.
type Translator interface {
	// TranslateUpstreamNodes translate Endpoints resources to APISIX Upstream nodes
	// according to the give port. Extra labels can be passed to filter the ultimate
	// upstream nodes.
	TranslateUpstreamNodes(*UpstreamArg) (apisixv1.UpstreamNodes, error)
	// TranslateUpstreamConfigV2beta3 translates ApisixUpstreamConfig (part of ApisixUpstream)
	// to APISIX Upstream, it doesn't fill the the Upstream metadata and nodes.
	TranslateUpstreamConfigV2beta3(*configv2beta3.ApisixUpstreamConfig) (*apisixv1.Upstream, error)
	// TranslateUpstreamConfigV2 translates ApisixUpstreamConfig (part of ApisixUpstream)
	// to APISIX Upstream, it doesn't fill the the Upstream metadata and nodes.
	TranslateUpstreamConfigV2(*configv2.ApisixUpstreamConfig) (*apisixv1.Upstream, error)
	// TranslateUpstream composes an upstream according to the
	// given namespace, name (searching Service/Endpoints) and port (filtering Endpoints).
	// The returned Upstream doesn't have metadata info.
	// It doesn't assign any metadata fields, so it's caller's responsibility to decide
	// the metadata.
	// Note the subset is used to filter the ultimate node list, only pods whose labels
	// matching the subset labels (defined in ApisixUpstream) will be selected.
	// When the subset is not found, the node list will be empty. When the subset is empty,
	// all pods IP will be filled.
	TranslateUpstream(*UpstreamArg) (*apisixv1.Upstream, error)
	// TranslateIngress composes a couple of APISIX Routes and upstreams according
	// to the given Ingress resource.
	TranslateIngress(kube.Ingress, ...bool) (*TranslateContext, error)
	// TranslateRouteV2beta2 translates the configv2beta2.ApisixRoute object into several Route,
	// and Upstream resources.
	TranslateRouteV2beta2(*configv2beta2.ApisixRoute) (*TranslateContext, error)
	// TranslateRouteV2beta2NotStrictly translates the configv2beta2.ApisixRoute object into several Route,
	// and Upstream  resources not strictly, only used for delete event.
	TranslateRouteV2beta2NotStrictly(*configv2beta2.ApisixRoute) (*TranslateContext, error)
	// TranslateRouteV2beta3 translates the configv2beta3.ApisixRoute object into several Route,
	// Upstream and PluginConfig resources.
	TranslateRouteV2beta3(*configv2beta3.ApisixRoute) (*TranslateContext, error)
	// TranslateRouteV2beta3NotStrictly translates the configv2beta3.ApisixRoute object into several Route,
	// Upstream and PluginConfig resources not strictly, only used for delete event.
	TranslateRouteV2beta3NotStrictly(*configv2beta3.ApisixRoute) (*TranslateContext, error)
	// TranslateRouteV2 translates the configv2.ApisixRoute object into several Route,
	// Upstream and PluginConfig resources.
	TranslateRouteV2(*configv2.ApisixRoute) (*TranslateContext, error)
	// TranslateRouteV2NotStrictly translates the configv2.ApisixRoute object into several Route,
	// Upstream and PluginConfig resources not strictly, only used for delete event.
	TranslateRouteV2NotStrictly(*configv2.ApisixRoute) (*TranslateContext, error)
	// TranslateSSLV2Beta3 translates the configv2beta3.ApisixTls object into the APISIX SSL resource.
	TranslateSSLV2Beta3(*configv2beta3.ApisixTls) (*apisixv1.Ssl, error)
	// TranslateSSLV2 translates the configv2.ApisixTls object into the APISIX SSL resource.
	TranslateSSLV2(*configv2.ApisixTls) (*apisixv1.Ssl, error)
	// TranslateClusterConfig translates the configv2beta3.ApisixClusterConfig object into the APISIX
	// Global Rule resource.
	TranslateClusterConfigV2beta3(*configv2beta3.ApisixClusterConfig) (*apisixv1.GlobalRule, error)
	// TranslateClusterConfigV2 translates the configv2.ApisixClusterConfig object into the APISIX
	// Global Rule resource.
	TranslateClusterConfigV2(*configv2.ApisixClusterConfig) (*apisixv1.GlobalRule, error)
	// TranslateApisixConsumer translates the configv2beta3.APisixConsumer object into the APISIX Consumer
	// resource.
	TranslateApisixConsumerV2beta3(*configv2beta3.ApisixConsumer) (*apisixv1.Consumer, error)
	// TranslateApisixConsumerV2 translates the configv2beta3.APisixConsumer object into the APISIX Consumer
	// resource.
	TranslateApisixConsumerV2(ac *configv2.ApisixConsumer) (*apisixv1.Consumer, error)
	// TranslatePluginConfigV2beta3 translates the configv2.ApisixPluginConfig object into several PluginConfig
	// resources.
	TranslatePluginConfigV2beta3(*configv2beta3.ApisixPluginConfig) (*TranslateContext, error)
	// TranslatePluginConfigV2beta3NotStrictly translates the configv2beta3.ApisixPluginConfig object into several PluginConfig
	// resources not strictly, only used for delete event.
	TranslatePluginConfigV2beta3NotStrictly(*configv2beta3.ApisixPluginConfig) (*TranslateContext, error)
	// TranslatePluginConfigV2 translates the configv2.ApisixPluginConfig object into several PluginConfig
	// resources.
	TranslatePluginConfigV2(*configv2.ApisixPluginConfig) (*TranslateContext, error)
	// TranslatePluginConfigV2NotStrictly translates the configv2.ApisixPluginConfig object into several PluginConfig
	// resources not strictly, only used for delete event.
	TranslatePluginConfigV2NotStrictly(*configv2.ApisixPluginConfig) (*TranslateContext, error)
	// ExtractKeyPair extracts certificate and private key pair from secret
	// Supports APISIX style ("cert" and "key") and Kube style ("tls.crt" and "tls.key)
	ExtractKeyPair(s *corev1.Secret, hasPrivateKey bool) ([]byte, []byte, error)
}

// TranslatorOptions contains options to help Translator
// work well.
type TranslatorOptions struct {
	PodCache             types.PodCache
	PodLister            listerscorev1.PodLister
	EndpointLister       kube.EndpointLister
	ServiceLister        listerscorev1.ServiceLister
	ApisixUpstreamLister kube.ApisixUpstreamLister
	SecretLister         listerscorev1.SecretLister
	UseEndpointSlices    bool
	APIVersion           string
}

type translator struct {
	*TranslatorOptions
}

// NewTranslator initializes a APISIX CRD resources Translator.
func NewTranslator(opts *TranslatorOptions) Translator {
	return &translator{
		TranslatorOptions: opts,
	}
}

func (t *translator) TranslateUpstreamConfigV2beta3(au *configv2beta3.ApisixUpstreamConfig) (*apisixv1.Upstream, error) {
	ups := apisixv1.NewDefaultUpstream()
	if err := t.translateUpstreamScheme(au.Scheme, ups); err != nil {
		return nil, err
	}
	if err := t.translateUpstreamLoadBalancerV2beta3(au.LoadBalancer, ups); err != nil {
		return nil, err
	}
	if err := t.translateUpstreamHealthCheckV2beta3(au.HealthCheck, ups); err != nil {
		return nil, err
	}
	if err := t.translateUpstreamRetriesAndTimeoutV2beta3(au.Retries, au.Timeout, ups); err != nil {
		return nil, err
	}
	if err := t.translateClientTLSV2beta3(au.TLSSecret, ups); err != nil {
		return nil, err
	}
	return ups, nil
}

func (t *translator) TranslateUpstreamConfigV2(au *configv2.ApisixUpstreamConfig) (*apisixv1.Upstream, error) {
	ups := apisixv1.NewDefaultUpstream()
	if err := t.translateUpstreamScheme(au.Scheme, ups); err != nil {
		return nil, err
	}
	if err := t.translateUpstreamLoadBalancerV2(au.LoadBalancer, ups); err != nil {
		return nil, err
	}
	if err := t.translateUpstreamHealthCheckV2(au.HealthCheck, ups); err != nil {
		return nil, err
	}
	if err := t.translateUpstreamRetriesAndTimeoutV2(au.Retries, au.Timeout, ups); err != nil {
		return nil, err
	}
	if err := t.translateClientTLSV2(au.TLSSecret, ups); err != nil {
		return nil, err
	}
	return ups, nil
}

// namespace, name, subset string, port int32
func (t *translator) TranslateUpstream(arg *UpstreamArg) (*apisixv1.Upstream, error) {
	switch t.APIVersion {
	case config.ApisixV2beta3:
		return t.translateUpstreamV2beta3(arg)
	case config.ApisixV2:
		return t.translateUpstreamV2(arg)
	default:
		panic(fmt.Errorf("unsupported ApisixUpstream version %v", t.APIVersion))
	}
}

func (t *translator) TranslateIngress(ing kube.Ingress, args ...bool) (*TranslateContext, error) {
	var skipVerify = false
	if len(args) != 0 {
		skipVerify = args[0]
	}
	switch ing.GroupVersion() {
	case kube.IngressV1:
		return t.translateIngressV1(ing.V1(), skipVerify)
	case kube.IngressV1beta1:
		return t.translateIngressV1beta1(ing.V1beta1(), skipVerify)
	case kube.IngressExtensionsV1beta1:
		return t.translateIngressExtensionsV1beta1(ing.ExtensionsV1beta1(), skipVerify)
	default:
		return nil, fmt.Errorf("translator: source group version not supported: %s", ing.GroupVersion())
	}
}
