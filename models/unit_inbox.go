package models

func (u *Unit) GetPagedInbox(page int) (messages []Message, total int, pages int) {
	const limit = 50
	if page < 1 {
		page = 1
	}

	query := db.Model(&Message{}).Where("receiver_id = ?", u.ID)

	var total64 int64
	if err := query.Count(&total64).Error; err != nil {
		return nil, 0, 0
	}
	total = int(total64)
	if total == 0 {
		return []Message{}, 0, 0
	}

	offset := (page - 1) * limit
	if err := query.Order("id desc").Limit(limit).Offset(offset).Find(&messages).Error; err != nil {
		return nil, 0, 0
	}

	pages = (total + limit - 1) / limit
	return messages, total, pages
}

func (u *Unit) GetInboxMessage(id int) *Message {
	var msg Message
	if err := db.Where("receiver_id = ? AND id = ?", u.ID, id).First(&msg).Error; err != nil {
		return nil
	}
	return &msg
}
