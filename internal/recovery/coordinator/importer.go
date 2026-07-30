package coordinator

import (
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/importer/legacyreport"
)

// DefaultImporter adapts legacyreport.ImportJSON to LegacyImporter.
type DefaultImporter struct{}

func (DefaultImporter) ImportJSON(raw []byte, options legacyreport.Options) (legacyreport.Result, error) {
	return legacyreport.ImportJSON(raw, options)
}
