package models

import (
	_ "github.com/jinzhu/gorm"
)

type UnitsByCountry struct {
	Country string `json:"country"`
	Count   int    `json:"units"`
}

func GetUnitsByCountry() ([]UnitsByCountry, error) {
	results := make([]UnitsByCountry, 0)
	if err := db.Raw("SELECT country,COUNT(id) AS count FROM units GROUP BY country ORDER BY count DESC").Scan(&results).Error; err != nil {
		return nil, err
	}
	return results, nil
}

// GetPagedUnits returns a page of units, total number of units and total pages.
// Uses a fixed limit of 25 per page to preserve previous behavior.
func GetPagedUnits(page int) (units []Unit, total int, pages int) {
	const limit = 25
	if page < 1 {
		page = 1
	}

	var total64 int64
	if err := db.Model(&Unit{}).Count(&total64).Error; err != nil {
		return nil, 0, 0
	}
	total = int(total64)
	if total == 0 {
		return []Unit{}, 0, 0
	}

	offset := (page - 1) * limit
	if err := db.Order("id desc").Limit(limit).Offset(offset).Find(&units).Error; err != nil {
		return nil, 0, 0
	}

	pages = (total + limit - 1) / limit
	return units, total, pages
}

func FindUnit(id uint) *Unit {
	var unit Unit
	if err := db.Find(&unit, id).Error; err != nil {
		return nil
	}
	return &unit
}

func FindUnitByFingerprint(fingerprint string) *Unit {
	var unit Unit
	if fingerprint == "" {
		return nil
	} else if err := db.Where("fingerprint = ?", fingerprint).Take(&unit).Error; err != nil {
		return nil
	}
	return &unit
}
