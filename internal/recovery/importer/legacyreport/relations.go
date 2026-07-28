package legacyreport

import (
	"fmt"
	"strings"
)

func relatedTargetIDs(ctx *importContext, ent orderedEntity) (related []string, limitations []string, warnings []string) {
	related = []string{}
	switch ent.entityKind {
	case "partition":
		if diskNum, ok := parseLocatorInt(ent.locators, "disk_number"); ok {
			if diskID, ok := ctx.diskByNumber[diskNum]; ok {
				related = append(related, diskID)
			} else {
				msg := fmt.Sprintf("partition %s has disk_number %d with no matching disk target", ent.sourcePath, diskNum)
				warnings = append(warnings, msg)
				limitations = append(limitations, msg)
			}
		}
	case "windows_installation":
		if letter, ok := driveLetterFromPath(ent.locators["root"]); ok {
			related, limitations, warnings = appendExactLetterRelation(ctx, related, limitations, warnings, letter, ent.sourcePath, "windows installation root")
		}
	case "boot_store":
		if letter, ok := driveLetterFromPath(ent.locators["path"]); ok {
			related, limitations, warnings = appendExactLetterRelation(ctx, related, limitations, warnings, letter, ent.sourcePath, "boot store path")
		}
	case "bitlocker_volume":
		if letter, ok := driveLetterFromPath(ent.locators["mount_point"]); ok {
			related, limitations, warnings = appendExactLetterRelation(ctx, related, limitations, warnings, letter, ent.sourcePath, "bitlocker mount point")
		}
	}
	return related, limitations, warnings
}

func appendExactLetterRelation(
	ctx *importContext,
	related, limitations, warnings []string,
	letter, sourcePath, kind string,
) ([]string, []string, []string) {
	matches := ctx.partitionByLetter[letter]
	switch len(matches) {
	case 1:
		related = append(related, matches[0])
	case 0:
		msg := fmt.Sprintf("%s %s drive letter %s has no matching partition target", kind, sourcePath, letter)
		warnings = append(warnings, msg)
		limitations = append(limitations, msg)
	default:
		msg := fmt.Sprintf("%s %s drive letter %s matches %d partitions; relation omitted", kind, sourcePath, letter, len(matches))
		warnings = append(warnings, msg)
		limitations = append(limitations, msg)
	}
	return related, limitations, warnings
}

func driveLetterFromPath(path string) (string, bool) {
	if !isUsableLocator(path) {
		return "", false
	}
	trimmed := strings.TrimSpace(path)
	if len(trimmed) >= 2 && trimmed[1] == ':' {
		return normalizeDriveLetterLocator(string(trimmed[0]))
	}
	// Bare letter forms such as "C".
	return normalizeDriveLetterLocator(trimmed)
}
