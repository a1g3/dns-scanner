package models

import (
	"fmt"
	"net"
)

type ToString interface {
	ToString() string
}

type SpfFragment struct {
	Raw string

	ToString
}

type SpfMechanism struct {
	Qualifier Qualifier
	Contents  string

	SpfFragment
}

type IncludeSpfFragment struct {
	DomainSpec
	SpfMechanism
}

func (include *IncludeSpfFragment) ToString() string {
	return fmt.Sprintf("%sinclude:%s", qualifierToString(include.Qualifier), include.Contents)
}

func qualifierToString(qualifier Qualifier) string {
	switch qualifier {
	case Pass:
		return ""
	case Neutral:
		return "~"
	case SoftFail:
		return "?"
	case HardFail:
		return "-"
	}
	return ""
}

type HeaderSpfFragment struct {
	Contents string
}

func (header HeaderSpfFragment) ToString() string {
	return "v=spf1"
}

type UnparseableSpfFragment struct {
	SpfFragment
}

func (unknown UnparseableSpfFragment) ToString() string {
	return unknown.Raw
}

type AllSpfFragment struct {
	SpfMechanism
}

func (all AllSpfFragment) ToString() string {
	return fmt.Sprintf("%sall", qualifierToString(all.Qualifier))
}

type ASpfFragment struct {
	DomainSpec
	SpfMechanism
}

func (all ASpfFragment) ToString() string {
	return fmt.Sprintf("%sa:%s", qualifierToString(all.Qualifier), all.Contents)
}

type MxSpfFragment struct {
	DomainSpec
	SpfMechanism
}

func (mx MxSpfFragment) ToString() string {
	return fmt.Sprintf("%smx:%s", qualifierToString(mx.Qualifier), mx.Contents)
}

type PtrSpfFragment struct {
	DomainSpec
	SpfMechanism
}

func (ptr PtrSpfFragment) ToString() string {
	return fmt.Sprintf("%sptr", qualifierToString(ptr.Qualifier))
}

type ExistSpfFragment struct {
	DomainSpec
	SpfMechanism
}

func (exist ExistSpfFragment) ToString() string {
	return fmt.Sprintf("%sexist:%s", qualifierToString(exist.Qualifier), exist.Contents)
}

type RedirectSpfFragment struct {
	Domain string

	DomainSpec
	SpfFragment
}

func (redirect RedirectSpfFragment) ToString() string {
	return fmt.Sprintf("redirect=%s", redirect.Domain)
}

type ExplanationSpfFragment struct {
	Domain string

	SpfFragment
}

func (explanation ExplanationSpfFragment) ToString() string {
	return fmt.Sprintf("exp=%s", explanation.Domain)
}

type Ip6SpfFragment struct {
	Ip4SpfFragment
}

func (ip6 Ip6SpfFragment) ToString() string {
	return fmt.Sprintf("%sip6:%s", qualifierToString(ip6.Qualifier), ip6.Ip.String())
}

type Ip4SpfFragment struct {
	Qualifier Qualifier
	Ip        net.IP
	Cidr      net.IPNet

	SpfMechanism
}

func (ip4 Ip4SpfFragment) ToString() string {
	return fmt.Sprintf("%sip4:%s", qualifierToString(ip4.Qualifier), ip4.Ip.String())
}

type DomainSpec struct {
	ContainsMacros bool
}

type Qualifier int

const (
	Pass     Qualifier = 1
	Neutral  Qualifier = 2
	SoftFail Qualifier = 3
	HardFail Qualifier = 4
)
