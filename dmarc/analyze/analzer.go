package analyze

import (
	"dnsScanner/models"

	"golang.org/x/exp/slices"
)

type DmarcVisitor struct {
	Validation []models.DmarcAnalyzerResults

	Request         string
	ADkim           string
	ASpf            string
	SRequest        string
	AInterval       int
	Percent         int
	FailureOptions  string
	FormatFragment  string
	ReportAggregate string
	ReportFailure   string

	stack []string
}

func (dv *DmarcVisitor) VisitDmarc(frag *models.DMARC) {
	dv.AInterval = -1
	dv.Percent = -1

	if frag.Request != nil {
		dv.Request = frag.Request.Policy

		if frag.Request.Policy == "none" {
			dv.Validation = append(dv.Validation, models.DmarcAnalyzerResults{
				Rule:     models.POLICY_NONE,
				Severity: models.WARNING,
				Message:  "Policy is set to none",
			})
		}
	}

	if frag.Frag != nil {
		(*frag.Frag).Accept(dv)
	}
}

func (dv *DmarcVisitor) VisitSrequest(frag *models.SrequestFragment) {
	if slices.Contains(dv.stack, "srequest") {
		dv.Validation = append(dv.Validation, models.DmarcAnalyzerResults{
			Rule:     models.DUPLICATE_FRAGMENT,
			Severity: models.ERROR,
			Message:  "Dupicate fragment srequest",
		})
	}

	dv.stack = append(dv.stack, "srequest")

	dv.SRequest = frag.Value

	if frag.Next != nil {
		(*frag.Next).Accept(dv)
	}
}

func (dv *DmarcVisitor) VisitDkim(frag *models.ADkimFragment) {
	if slices.Contains(dv.stack, "adkim") {
		dv.Validation = append(dv.Validation, models.DmarcAnalyzerResults{
			Rule:     models.DUPLICATE_FRAGMENT,
			Severity: models.ERROR,
			Message:  "Dupicate fragment adkim",
		})
	}

	dv.stack = append(dv.stack, "adkim")

	dv.ADkim = frag.Value

	if frag.Next != nil {
		(*frag.Next).Accept(dv)
	}
}

func (dv *DmarcVisitor) VisitSpf(frag *models.ADSpfFragment) {
	if slices.Contains(dv.stack, "spf") {
		dv.Validation = append(dv.Validation, models.DmarcAnalyzerResults{
			Rule:     models.DUPLICATE_FRAGMENT,
			Severity: models.ERROR,
			Message:  "Dupicate fragment spf",
		})
	}

	dv.stack = append(dv.stack, "spf")

	dv.ASpf = frag.Value

	if frag.Next != nil {
		(*frag.Next).Accept(dv)
	}
}

func (dv *DmarcVisitor) VisitAInterval(frag *models.AIntervalFragment) {
	if slices.Contains(dv.stack, "interval") {
		dv.Validation = append(dv.Validation, models.DmarcAnalyzerResults{
			Rule:     models.DUPLICATE_FRAGMENT,
			Severity: models.ERROR,
			Message:  "Dupicate fragment interval",
		})
	}

	dv.stack = append(dv.stack, "interval")

	if frag.Value > 9 || frag.Value < 0 {
		dv.Validation = append(dv.Validation, models.DmarcAnalyzerResults{
			Rule:     models.INVALID_NUMBER,
			Severity: models.ERROR,
			Message:  "Invalid number for ri",
		})
	} else {
		dv.AInterval = frag.Value
	}

	if frag.Next != nil {
		(*frag.Next).Accept(dv)
	}
}

func (dv *DmarcVisitor) VisitFailureOptions(frag *models.FailureOptionsFragment) {
	if slices.Contains(dv.stack, "failure-options") {
		dv.Validation = append(dv.Validation, models.DmarcAnalyzerResults{
			Rule:     models.DUPLICATE_FRAGMENT,
			Severity: models.ERROR,
			Message:  "Dupicate fragment failure-options",
		})
	}

	dv.stack = append(dv.stack, "failure-options")

	dv.FailureOptions = frag.Value

	if frag.Next != nil {
		(*frag.Next).Accept(dv)
	}
}

func (dv *DmarcVisitor) VisitFormat(frag *models.FormatFragment) {
	if slices.Contains(dv.stack, "format") {
		dv.Validation = append(dv.Validation, models.DmarcAnalyzerResults{
			Rule:     models.DUPLICATE_FRAGMENT,
			Severity: models.ERROR,
			Message:  "Dupicate fragment format",
		})
	}

	dv.stack = append(dv.stack, "format")

	dv.FormatFragment = frag.Value

	if frag.Next != nil {
		(*frag.Next).Accept(dv)
	}
}

func (dv *DmarcVisitor) VisitReportAggregate(frag *models.ReportAggregateFragment) {
	if slices.Contains(dv.stack, "report-aggregate") {
		dv.Validation = append(dv.Validation, models.DmarcAnalyzerResults{
			Rule:     models.DUPLICATE_FRAGMENT,
			Severity: models.ERROR,
			Message:  "Dupicate fragment report-aggregate",
		})
	}

	dv.stack = append(dv.stack, "report-aggregate")

	dv.ReportAggregate = frag.Value

	if frag.Next != nil {
		(*frag.Next).Accept(dv)
	}
}

func (dv *DmarcVisitor) VisitReportFailure(frag *models.ReportFailureFragment) {
	if slices.Contains(dv.stack, "report-failure") {
		dv.Validation = append(dv.Validation, models.DmarcAnalyzerResults{
			Rule:     models.DUPLICATE_FRAGMENT,
			Severity: models.ERROR,
			Message:  "Dupicate fragment report-failure",
		})
	}

	dv.stack = append(dv.stack, "report-failure")

	dv.ReportFailure = frag.Value

	if frag.Next != nil {
		(*frag.Next).Accept(dv)
	}
}

func (dv *DmarcVisitor) VisitPercent(frag *models.PercentFragment) {
	if slices.Contains(dv.stack, "percent") {
		dv.Validation = append(dv.Validation, models.DmarcAnalyzerResults{
			Rule:     models.DUPLICATE_FRAGMENT,
			Severity: models.ERROR,
			Message:  "Dupicate fragment percent",
		})
	}

	dv.stack = append(dv.stack, "percent")

	if frag.Value > 100 || frag.Value < 0 {
		dv.Validation = append(dv.Validation, models.DmarcAnalyzerResults{
			Rule:     models.INVALID_NUMBER,
			Severity: models.ERROR,
			Message:  "Invalid number for pct",
		})
	} else {
		dv.Percent = frag.Value
	}

	if frag.Next != nil {
		(*frag.Next).Accept(dv)
	}
}
