package models

type ParsedSpfFragment interface {
}

type ISPFParser interface {
	Execute(raw string, fragment string, qualifier Qualifier) ParsedSpfFragment
	SetNext(worker ISPFParser)
}
