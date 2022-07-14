// Copyright 2022 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	sysctlInclude     = kingpin.Flag("collector.sysctl.include", "Select sysctl metrics to include").Strings()
	sysctlIncludeInfo = kingpin.Flag("collector.sysctl.include-info", "Select sysctl metrics to include as info metrics").Strings()

	sysctlInfoDesc = prometheus.NewDesc(prometheus.BuildFQName(namespace, "sysctl", "info"), "sysctl info", []string{"name", "value", "index"}, nil)
)

type sysctlCollector struct {
	fs      procfs.FS
	logger  log.Logger
	sysctls []*Sysctl
}

func init() {
	registerCollector("sysctl", defaultEnabled, NewSysctlCollector)
}

func NewSysctlCollector(logger log.Logger) (Collector, error) {
	fs, err := procfs.NewFS(*procPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sysfs: %w", err)
	}
	c := &sysctlCollector{
		logger:  logger,
		fs:      fs,
		sysctls: []*Sysctl{},
	}

	for _, include := range *sysctlInclude {
		sysctl, err := NewSysctl(include, true)
		if err != nil {
			return nil, err
		}
		c.sysctls = append(c.sysctls, sysctl)
	}

	for _, include := range *sysctlIncludeInfo {
		sysctl, err := NewSysctl(include, false)
		if err != nil {
			return nil, err
		}
		c.sysctls = append(c.sysctls, sysctl)
	}
	return c, nil
}

func (c *sysctlCollector) Update(ch chan<- prometheus.Metric) error {
	for _, sysctl := range c.sysctls {
		metrics, err := c.NewMetrics(sysctl)
		if err != nil {
			return err
		}

		for _, metric := range metrics {
			ch <- metric
		}
	}
	return nil
}

func (c *sysctlCollector) NewMetrics(sysctl *Sysctl) ([]prometheus.Metric, error) {
	var (
		values interface{}
		length int
		err    error
	)

	if sysctl.numeric {
		values, err = c.fs.SysctlInts(sysctl.name)
		if err != nil {
			return nil, fmt.Errorf("error obtaining sysctl info: %w", err)
		}
		length = len(values.([]int))
	} else {
		values, err = c.fs.SysctlStrings(sysctl.name)
		if err != nil {
			return nil, fmt.Errorf("error obtaining sysctl info: %w", err)
		}
		length = len(values.([]string))
	}

	switch length {
	case 0:
		return nil, fmt.Errorf("sysctl %s has no values", sysctl.name)
	case 1:
		if len(sysctl.keys) > 0 {
			return nil, fmt.Errorf("sysctl %s has only one value, but expected %v", sysctl.name, sysctl.keys)
		}
		return []prometheus.Metric{sysctl.NewConstMetric(values)}, nil

	default:

		if len(sysctl.keys) == 0 {
			return sysctl.NewIndexedMetrics(values), nil
		}

		if length != len(sysctl.keys) {
			return nil, fmt.Errorf("sysctl %s has %d keys but only %d defined in f lag", sysctl.name, length, len(sysctl.keys))
		}

		return sysctl.NewMappedMetrics(values)
	}
}

type Sysctl struct {
	numeric bool
	name    string
	keys    []string
}

func NewSysctl(include string, numeric bool) (*Sysctl, error) {
	parts := strings.SplitN(include, ":", 2)
	s := &Sysctl{
		numeric: numeric,
		name:    parts[0],
	}
	if len(parts) == 2 {
		s.keys = strings.Split(parts[1], ",")
		s.name = parts[0]
	}
	return s, nil
}

func (sysctl *Sysctl) MetricName() string {
	return SanitizeMetricName(sysctl.name)
}

func (sysctl *Sysctl) NewConstMetric(v interface{}) prometheus.Metric {
	if sysctl.numeric {
		return prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(namespace, "sysctl", sysctl.MetricName()),
				fmt.Sprintf("sysctl %s", sysctl.name),
				nil, nil),
			prometheus.UntypedValue,
			float64(v.([]int)[0]))
	}
	return prometheus.MustNewConstMetric(
		sysctlInfoDesc,
		prometheus.UntypedValue,
		1.0,
		sysctl.name,
		v.([]string)[0],
		"0",
	)
}

func (sysctl *Sysctl) NewIndexedMetrics(v interface{}) []prometheus.Metric {
	desc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sysctl", sysctl.MetricName()),
		fmt.Sprintf("sysctl %s", sysctl.name),
		[]string{"index"}, nil,
	)
	switch values := v.(type) {
	case []int:
		metrics := make([]prometheus.Metric, len(values))
		for i, n := range values {
			metrics[i] = prometheus.MustNewConstMetric(desc, prometheus.UntypedValue, float64(n), strconv.Itoa(i))
		}
		return metrics
	case []string:
		metrics := make([]prometheus.Metric, len(values))
		for i, str := range values {
			metrics[i] = prometheus.MustNewConstMetric(sysctlInfoDesc, prometheus.UntypedValue, 1.0, sysctl.name, str, strconv.Itoa(i))
		}
		return metrics
	default:
		panic(fmt.Sprintf("unexpected type %T", values))
	}
}

func (sysctl *Sysctl) NewMappedMetrics(v interface{}) ([]prometheus.Metric, error) {
	switch values := v.(type) {
	case []int:
		metrics := make([]prometheus.Metric, len(values))
		for i, n := range values {
			key := sysctl.keys[i]
			desc := prometheus.NewDesc(
				prometheus.BuildFQName(namespace, "sysctl", sysctl.MetricName()+"_"+key),
				fmt.Sprintf("sysctl %s, field %d", sysctl.name, i),
				nil,
				nil,
			)
			metrics[i] = prometheus.MustNewConstMetric(desc, prometheus.UntypedValue, float64(n))
		}
		return metrics, nil
	case []string:
		return nil, fmt.Errorf("mapped sysctl string values not supported")
	default:
		return nil, fmt.Errorf("unexpected type %T", values)
	}
}
