package models

import "net"

type SpfFragment struct {
	Raw string
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

type HeaderSpfFragment struct {
	Contents string
}

type UnparseableSpfFragment struct {
	SpfFragment
}

type AllSpfFragment struct {
	SpfMechanism
}

type ASpfFragment struct {
	DomainSpec
	SpfMechanism
}

type MxSpfFragment struct {
	DomainSpec
	SpfMechanism
}

type PtrSpfFragment struct {
	DomainSpec
	SpfMechanism
}

type ExistSpfFragment struct {
	DomainSpec
	SpfMechanism
}

type RedirectSpfFragment struct {
	Domain string

	DomainSpec
	SpfFragment
}

type ExplanationSpfFragment struct {
	Domain string

	SpfFragment
}

type Ip6SpfFragment struct {
	Ip4SpfFragment
}

type Ip4SpfFragment struct {
	Qualifier Qualifier
	Ip        net.IP
	Cidr      net.IPNet

	SpfMechanism
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
