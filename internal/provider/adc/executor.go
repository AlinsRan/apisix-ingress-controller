// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package adc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/api7/gopkg/pkg/log"
	"go.uber.org/zap"

	adctypes "github.com/apache/apisix-ingress-controller/api/adc"
	"github.com/apache/apisix-ingress-controller/internal/types"
)

type ADCExecutor interface {
	Execute(ctx context.Context, mode string, config adcConfig, args []string) error
}

type DefaultADCExecutor struct {
	sync.Mutex
}

func (e *DefaultADCExecutor) Execute(ctx context.Context, mode string, config adcConfig, args []string) error {
	e.Lock()
	defer e.Unlock()

	return e.runADC(ctx, mode, config, args)
}

func (e *DefaultADCExecutor) runADC(ctx context.Context, mode string, config adcConfig, args []string) error {
	var execErrs = types.ADCExecutionError{
		Name: config.Name,
	}

	for _, addr := range config.ServerAddrs {
		if err := e.runForSingleServerWithTimeout(ctx, addr, mode, config, args); err != nil {
			log.Errorw("failed to run adc for server", zap.String("server", addr), zap.Error(err))
			var execErr types.ADCExecutionServerAddrError
			if errors.As(err, &execErr) {
				execErrs.FailedErrors = append(execErrs.FailedErrors, execErr)
			} else {
				execErrs.FailedErrors = append(execErrs.FailedErrors, types.ADCExecutionServerAddrError{
					ServerAddr: addr,
					Err:        err.Error(),
				})
			}
		}
	}
	if len(execErrs.FailedErrors) > 0 {
		return execErrs
	}
	return nil
}

func (e *DefaultADCExecutor) runForSingleServerWithTimeout(ctx context.Context, serverAddr, mode string, config adcConfig, args []string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return e.runForSingleServer(ctx, serverAddr, mode, config, args)
}

func (e *DefaultADCExecutor) runForSingleServer(ctx context.Context, serverAddr, mode string, config adcConfig, args []string) error {
	cmdArgs := append([]string{}, args...)
	if !config.TlsVerify {
		cmdArgs = append(cmdArgs, "--tls-skip-verify")
	}

	cmdArgs = append(cmdArgs, "--timeout", "15s")

	env := e.prepareEnv(serverAddr, mode, config.Token)

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "adc", cmdArgs...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = append(os.Environ(), env...)

	log.Debugw("running adc command",
		zap.String("command", strings.Join(cmd.Args, " ")),
		zap.Strings("env", filterSensitiveEnv(env)),
	)

	if err := cmd.Run(); err != nil {
		return e.buildCmdError(err, stdout.Bytes(), stderr.Bytes())
	}

	result, err := e.handleOutput(stdout.Bytes())
	if err != nil {
		log.Errorw("failed to handle adc output",
			zap.Error(err),
			zap.String("stdout", stdout.String()),
			zap.String("stderr", stderr.String()),
		)
		return fmt.Errorf("failed to handle adc output: %w", err)
	}
	if result.FailedCount > 0 && len(result.Failed) > 0 {
		log.Errorw("adc sync failed", zap.Any("result", result))
		return types.ADCExecutionServerAddrError{
			ServerAddr:     serverAddr,
			Err:            result.Failed[0].Reason,
			FailedStatuses: result.Failed,
		}
	}
	log.Debugw("adc sync success", zap.Any("result", result))
	return nil
}

func (e *DefaultADCExecutor) prepareEnv(serverAddr, mode, token string) []string {
	return []string{
		"ADC_EXPERIMENTAL_FEATURE_FLAGS=remote-state-file,parallel-backend-request",
		"ADC_RUNNING_MODE=ingress",
		"ADC_BACKEND=" + mode,
		"ADC_SERVER=" + serverAddr,
		"ADC_TOKEN=" + token,
	}
}

// filterSensitiveEnv filters out sensitive information from environment variables for logging
func filterSensitiveEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, envVar := range env {
		if strings.Contains(envVar, "ADC_TOKEN=") {
			filtered = append(filtered, "ADC_TOKEN=***")
		} else {
			filtered = append(filtered, envVar)
		}
	}
	return filtered
}

func (e *DefaultADCExecutor) buildCmdError(runErr error, stdout, stderr []byte) error {
	errMsg := string(stderr)
	if errMsg == "" {
		errMsg = string(stdout)
	}
	log.Errorw("failed to run adc",
		zap.Error(runErr),
		zap.String("output", string(stdout)),
		zap.String("stderr", string(stderr)),
	)
	return errors.New("failed to sync resources: " + errMsg + ", exit err: " + runErr.Error())
}

func (e *DefaultADCExecutor) handleOutput(output []byte) (*adctypes.SyncResult, error) {
	var result adctypes.SyncResult
	log.Debugw("adc output", zap.String("output", string(output)))
	if lines := bytes.Split(output, []byte{'\n'}); len(lines) > 0 {
		output = lines[len(lines)-1]
	}
	if err := json.Unmarshal(output, &result); err != nil {
		log.Errorw("failed to unmarshal adc output",
			zap.Error(err),
			zap.String("stdout", string(output)),
		)
		return nil, errors.New("failed to parse adc result: " + err.Error())
	}

	return &result, nil
}

func BuildADCExecuteArgs(filePath string, labels map[string]string, types []string) []string {
	args := []string{
		"sync",
		"-f", filePath,
	}
	for k, v := range labels {
		args = append(args, "--label-selector", k+"="+v)
	}
	for _, t := range types {
		args = append(args, "--include-resource-type", t)
	}
	return args
}
