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
	"bytes"
	"fmt"
	"strings"

	"go.uber.org/zap"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	networkingv1 "k8s.io/api/networking/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/apache/apisix-ingress-controller/pkg/id"
	kubev2 "github.com/apache/apisix-ingress-controller/pkg/kube/apisix/apis/config/v2"
	kubev2beta3 "github.com/apache/apisix-ingress-controller/pkg/kube/apisix/apis/config/v2beta3"
	apisixconst "github.com/apache/apisix-ingress-controller/pkg/kube/apisix/const"
	"github.com/apache/apisix-ingress-controller/pkg/kube/translation/annotations"
	"github.com/apache/apisix-ingress-controller/pkg/log"
	apisixv1 "github.com/apache/apisix-ingress-controller/pkg/types/apisix/v1"
)

const (
	_regexPriority = 100
)

func (t *translator) translateIngressV1(ing *networkingv1.Ingress) (*TranslateContext, error) {
	ctx := DefaultEmptyTranslateContext()
	plugins := t.translateAnnotations(ing.Annotations)
	annoExtractor := annotations.NewExtractor(ing.Annotations)
	useRegex := annoExtractor.GetBoolAnnotation(annotations.AnnotationsPrefix + "use-regex")
	enableWebsocket := annoExtractor.GetBoolAnnotation(annotations.AnnotationsPrefix + "enable-websocket")
	pluginConfigName := annoExtractor.GetStringAnnotation(annotations.AnnotationsPrefix + "plugin-config-name")

	// add https
	for _, tls := range ing.Spec.TLS {
		apisixTls := kubev2.ApisixTls{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ApisixTls",
				APIVersion: "apisix.apache.org/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%v-%v", ing.Name, "tls"),
				Namespace: ing.Namespace,
			},
			Spec: &kubev2.ApisixTlsSpec{},
		}
		for _, host := range tls.Hosts {
			apisixTls.Spec.Hosts = append(apisixTls.Spec.Hosts, kubev2.HostType(host))
		}
		apisixTls.Spec.Secret = kubev2.ApisixSecret{
			Name:      tls.SecretName,
			Namespace: ing.Namespace,
		}
		ssl, err := t.TranslateSSLV2(&apisixTls)
		if err != nil {
			log.Errorw("failed to translate ingress tls to apisix tls",
				zap.Error(err),
				zap.Any("ingress", ing),
			)
			return nil, err
		}
		ctx.AddSSL(ssl)
	}
	for _, rule := range ing.Spec.Rules {
		for _, pathRule := range rule.HTTP.Paths {
			var (
				ups *apisixv1.Upstream
				err error
			)
			if pathRule.Backend.Service != nil {
				var port intstr.IntOrString
				if pathRule.Backend.Service.Port.Name != "" {
					port = intstr.FromString(pathRule.Backend.Service.Port.Name)
				} else {
					port = intstr.FromInt(int(pathRule.Backend.Service.Port.Number))
				}
				ups, err = t.TranslateUpstream(
					&UpstreamArg{
						Namespace: ing.Namespace,
						Name:      pathRule.Backend.Service.Name,
						Port:      port,
					},
				)
				if err != nil {
					log.Errorw("failed to translate ingress backend to upstream",
						zap.Error(err),
						zap.Any("ingress", ing),
					)
					return nil, err
				}
				ctx.AddUpstream(ups)
			}
			uris := []string{pathRule.Path}
			var nginxVars []kubev2.ApisixRouteHTTPMatchExpr
			if pathRule.PathType != nil {
				if *pathRule.PathType == networkingv1.PathTypePrefix {
					// As per the specification of Ingress path matching rule:
					// if the last element of the path is a substring of the
					// last element in request path, it is not a match, e.g. /foo/bar
					// matches /foo/bar/baz, but does not match /foo/barbaz.
					// While in APISIX, /foo/bar matches both /foo/bar/baz and
					// /foo/barbaz.
					// In order to be conformant with Ingress specification, here
					// we create two paths here, the first is the path itself
					// (exact match), the other is path + "/*" (prefix match).
					prefix := pathRule.Path
					if strings.HasSuffix(prefix, "/") {
						prefix += "*"
					} else {
						prefix += "/*"
					}
					uris = append(uris, prefix)
				} else if *pathRule.PathType == networkingv1.PathTypeImplementationSpecific && useRegex {
					nginxVars = append(nginxVars, kubev2.ApisixRouteHTTPMatchExpr{
						Subject: kubev2.ApisixRouteHTTPMatchExprSubject{
							Scope: apisixconst.ScopePath,
						},
						Op:    apisixconst.OpRegexMatch,
						Value: &pathRule.Path,
					})
					uris = []string{"/*"}
				}
			}
			route := apisixv1.NewDefaultRoute()
			route.Name = composeIngressRouteName(ing.Namespace, ing.Name, rule.Host, pathRule.Path)
			route.ID = id.GenID(route.Name)
			route.Host = rule.Host
			route.Uris = uris
			route.EnableWebsocket = enableWebsocket
			if len(nginxVars) > 0 {
				routeVars, err := t.translateRouteMatchExprs(nginxVars)
				if err != nil {
					return nil, err
				}
				route.Vars = routeVars
				route.Priority = _regexPriority
			}
			if len(plugins) > 0 {
				route.Plugins = *(plugins.DeepCopy())
			}

			if pluginConfigName != "" {
				route.PluginConfigId = id.GenID(apisixv1.ComposePluginConfigName(ing.Namespace, pluginConfigName))
			}
			if ups != nil {
				route.UpstreamId = ups.ID
			}
			ctx.AddRoute(route)
		}
	}
	return ctx, nil
}

func (t *translator) translateIngressV1beta1(ing *networkingv1beta1.Ingress) (*TranslateContext, error) {
	ctx := DefaultEmptyTranslateContext()
	plugins := t.translateAnnotations(ing.Annotations)
	annoExtractor := annotations.NewExtractor(ing.Annotations)
	useRegex := annoExtractor.GetBoolAnnotation(annotations.AnnotationsPrefix + "use-regex")
	enableWebsocket := annoExtractor.GetBoolAnnotation(annotations.AnnotationsPrefix + "enable-websocket")
	pluginConfigName := annoExtractor.GetStringAnnotation(annotations.AnnotationsPrefix + "plugin-config-name")

	// add https
	for _, tls := range ing.Spec.TLS {
		apisixTls := kubev2beta3.ApisixTls{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ApisixTls",
				APIVersion: "apisix.apache.org/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%v-%v", ing.Name, "tls"),
				Namespace: ing.Namespace,
			},
			Spec: &kubev2beta3.ApisixTlsSpec{},
		}
		for _, host := range tls.Hosts {
			apisixTls.Spec.Hosts = append(apisixTls.Spec.Hosts, kubev2beta3.HostType(host))
		}
		apisixTls.Spec.Secret = kubev2beta3.ApisixSecret{
			Name:      tls.SecretName,
			Namespace: ing.Namespace,
		}
		ssl, err := t.TranslateSSLV2Beta3(&apisixTls)
		if err != nil {
			log.Errorw("failed to translate ingress tls to apisix tls",
				zap.Error(err),
				zap.Any("ingress", ing),
			)
			return nil, err
		}
		ctx.AddSSL(ssl)
	}
	for _, rule := range ing.Spec.Rules {
		for _, pathRule := range rule.HTTP.Paths {
			var (
				ups *apisixv1.Upstream
				err error
			)
			if pathRule.Backend.ServiceName != "" {
				ups, err = t.TranslateUpstream(
					&UpstreamArg{
						Namespace: ing.Namespace,
						Name:      pathRule.Backend.ServiceName,
						Port:      pathRule.Backend.ServicePort,
					},
				)
				if err != nil {
					log.Errorw("failed to translate ingress backend to upstream",
						zap.Error(err),
						zap.Any("ingress", ing),
					)
					return nil, err
				}
				ctx.AddUpstream(ups)
			}
			uris := []string{pathRule.Path}
			var nginxVars []kubev2.ApisixRouteHTTPMatchExpr
			if pathRule.PathType != nil {
				if *pathRule.PathType == networkingv1beta1.PathTypePrefix {
					// As per the specification of Ingress path matching rule:
					// if the last element of the path is a substring of the
					// last element in request path, it is not a match, e.g. /foo/bar
					// matches /foo/bar/baz, but does not match /foo/barbaz.
					// While in APISIX, /foo/bar matches both /foo/bar/baz and
					// /foo/barbaz.
					// In order to be conformant with Ingress specification, here
					// we create two paths here, the first is the path itself
					// (exact match), the other is path + "/*" (prefix match).
					prefix := pathRule.Path
					if strings.HasSuffix(prefix, "/") {
						prefix += "*"
					} else {
						prefix += "/*"
					}
					uris = append(uris, prefix)
				} else if *pathRule.PathType == networkingv1beta1.PathTypeImplementationSpecific && useRegex {
					nginxVars = append(nginxVars, kubev2.ApisixRouteHTTPMatchExpr{
						Subject: kubev2.ApisixRouteHTTPMatchExprSubject{
							Scope: apisixconst.ScopePath,
						},
						Op:    apisixconst.OpRegexMatch,
						Value: &pathRule.Path,
					})
					uris = []string{"/*"}
				}
			}
			route := apisixv1.NewDefaultRoute()
			route.Name = composeIngressRouteName(ing.Namespace, ing.Name, rule.Host, pathRule.Path)
			route.ID = id.GenID(route.Name)
			route.Host = rule.Host
			route.Uris = uris
			route.EnableWebsocket = enableWebsocket
			if len(nginxVars) > 0 {
				routeVars, err := t.translateRouteMatchExprs(nginxVars)
				if err != nil {
					return nil, err
				}
				route.Vars = routeVars
				route.Priority = _regexPriority
			}
			if len(plugins) > 0 {
				route.Plugins = *(plugins.DeepCopy())
			}

			if pluginConfigName != "" {
				route.PluginConfigId = id.GenID(apisixv1.ComposePluginConfigName(ing.Namespace, pluginConfigName))
			}
			if ups != nil {
				route.UpstreamId = ups.ID
			}
			ctx.AddRoute(route)
		}
	}
	return ctx, nil
}

func (t *translator) translateIngressExtensionsV1beta1(ing *extensionsv1beta1.Ingress) (*TranslateContext, error) {
	ctx := DefaultEmptyTranslateContext()
	plugins := t.translateAnnotations(ing.Annotations)
	annoExtractor := annotations.NewExtractor(ing.Annotations)
	useRegex := annoExtractor.GetBoolAnnotation(annotations.AnnotationsPrefix + "use-regex")
	enableWebsocket := annoExtractor.GetBoolAnnotation(annotations.AnnotationsPrefix + "enable-websocket")
	pluginConfigName := annoExtractor.GetStringAnnotation(annotations.AnnotationsPrefix + "plugin-config-name")

	for _, rule := range ing.Spec.Rules {
		for _, pathRule := range rule.HTTP.Paths {
			var (
				ups *apisixv1.Upstream
				err error
			)
			if pathRule.Backend.ServiceName != "" {
				// Structure here is same to ingress.extensions/v1beta1, so just use this method.
				ups, err = t.TranslateUpstream(
					&UpstreamArg{
						Namespace: ing.Namespace,
						Name:      pathRule.Backend.ServiceName,
						Port:      pathRule.Backend.ServicePort,
					})
				if err != nil {
					log.Errorw("failed to translate ingress backend to upstream",
						zap.Error(err),
						zap.Any("ingress", ing),
					)
					return nil, err
				}
				ctx.AddUpstream(ups)
			}
			uris := []string{pathRule.Path}
			var nginxVars []kubev2.ApisixRouteHTTPMatchExpr
			if pathRule.PathType != nil {
				if *pathRule.PathType == extensionsv1beta1.PathTypePrefix {
					// As per the specification of Ingress path matching rule:
					// if the last element of the path is a substring of the
					// last element in request path, it is not a match, e.g. /foo/bar
					// matches /foo/bar/baz, but does not match /foo/barbaz.
					// While in APISIX, /foo/bar matches both /foo/bar/baz and
					// /foo/barbaz.
					// In order to be conformant with Ingress specification, here
					// we create two paths here, the first is the path itself
					// (exact match), the other is path + "/*" (prefix match).
					prefix := pathRule.Path
					if strings.HasSuffix(prefix, "/") {
						prefix += "*"
					} else {
						prefix += "/*"
					}
					uris = append(uris, prefix)
				} else if *pathRule.PathType == extensionsv1beta1.PathTypeImplementationSpecific && useRegex {
					nginxVars = append(nginxVars, kubev2.ApisixRouteHTTPMatchExpr{
						Subject: kubev2.ApisixRouteHTTPMatchExprSubject{
							Scope: apisixconst.ScopePath,
						},
						Op:    apisixconst.OpRegexMatch,
						Value: &pathRule.Path,
					})
					uris = []string{"/*"}
				}
			}
			route := apisixv1.NewDefaultRoute()
			route.Name = composeIngressRouteName(ing.Namespace, ing.Name, rule.Host, pathRule.Path)
			route.ID = id.GenID(route.Name)
			route.Host = rule.Host
			route.Uris = uris
			route.EnableWebsocket = enableWebsocket
			if len(nginxVars) > 0 {
				routeVars, err := t.translateRouteMatchExprs(nginxVars)
				if err != nil {
					return nil, err
				}
				route.Vars = routeVars
				route.Priority = _regexPriority
			}
			if len(plugins) > 0 {
				route.Plugins = *(plugins.DeepCopy())
			}

			if pluginConfigName != "" {
				route.PluginConfigId = id.GenID(apisixv1.ComposePluginConfigName(ing.Namespace, pluginConfigName))
			}

			if ups != nil {
				route.UpstreamId = ups.ID
			}
			ctx.AddRoute(route)
		}
	}
	return ctx, nil
}

// In the past, we used host + path directly to form its route name for readability,
// but this method can cause problems in some scenarios.
// For example, the generated name is too long.
// The current APISIX limit its maximum length to 100.
// ref: https://github.com/apache/apisix-ingress-controller/issues/781
// We will construct the following structure for easy reading and debugging.
// ing_namespace_ingressName_id
func composeIngressRouteName(namespace, name, host, path string) string {
	pID := id.GenID(host + path)
	p := make([]byte, 0, len(namespace)+len(name)+len("ing")+len(pID)+3)
	buf := bytes.NewBuffer(p)

	buf.WriteString("ing")
	buf.WriteByte('_')
	buf.WriteString(namespace)
	buf.WriteByte('_')
	buf.WriteString(name)
	buf.WriteByte('_')
	buf.WriteString(pID)

	return buf.String()
}
