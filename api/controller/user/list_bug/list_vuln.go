package controller_list_bug

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"

	domain_listbug "xops-admin/domain/user/list_bug"
	"xops-admin/helper/errorenum"
	"xops-admin/helper/payload"
	"xops-admin/model"
)

type ListVulnerabilityHandler struct {
	usecase domain_listbug.ListVulnerabilityUseCase
}

func NewListVulnerabilityHandler(u domain_listbug.ListVulnerabilityUseCase) *ListVulnerabilityHandler {
	return &ListVulnerabilityHandler{usecase: u}
}

// Create
func (h *ListVulnerabilityHandler) Create(c *fiber.Ctx) error {
	var bug model.ListVulnerability
	var response payload.Response

	if err := c.BodyParser(&bug); err != nil {
		response = payload.NewErrorResponse(errorenum.SomethingError)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	// set timestamp
	bug.CreatedAt = time.Now()
	bug.UpdatedAt = time.Now()

	if err := h.usecase.Create(c.Context(), &bug); err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	response = payload.NewSuccessResponse(bug, errorenum.OKSuccess)
	return c.Status(fiber.StatusCreated).JSON(response)
}

// GetByID
func (h *ListVulnerabilityHandler) GetByID(c *fiber.Ctx) error {
	var response payload.Response
	idStr := c.Params("id")

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		response = payload.NewErrorResponse(errorenum.SomethingError)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	vuln, err := h.usecase.GetByID(c.Context(), id)
	if err != nil {
		response = payload.NewErrorResponse(errorenum.SomethingError)
		return c.Status(fiber.StatusNotFound).JSON(response)
	}

	response = payload.NewSuccessResponse(vuln, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)
}

// Update
func (h *ListVulnerabilityHandler) Update(c *fiber.Ctx) error {
	var vuln model.ListVulnerability
	var response payload.Response

	if err := c.BodyParser(&vuln); err != nil {
		response = payload.NewErrorResponse(errorenum.SomethingError)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	if err := h.usecase.Update(c.Context(), &vuln); err != nil {
		response = payload.NewErrorResponse(errorenum.SomethingError)
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	response = payload.NewSuccessResponse(vuln, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)
}

// Delete
func (h *ListVulnerabilityHandler) Delete(c *fiber.Ctx) error {
	var response payload.Response
	idStr := c.Params("id")

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		response = payload.NewErrorResponse(errorenum.SomethingError)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	if err := h.usecase.Delete(c.Context(), id); err != nil {
		response = payload.NewErrorResponse(errorenum.SomethingError)
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	response = payload.NewSuccessResponse(nil, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)
}

// List
func (h *ListVulnerabilityHandler) List(c *fiber.Ctx) error {
	var response payload.Response

	cursorIDStr := c.Query("cursor_id", "0")
	limitStr := c.Query("limit", "5")
	direction := c.Query("direction", "next") // default next

	cursorID, _ := strconv.Atoi(cursorIDStr)
	limit, _ := strconv.Atoi(limitStr)

	results, hasMore, nextCursor, prevCursor, err := h.usecase.List(c.Context(), cursorID, limit, direction)
	if err != nil {
		response = payload.NewErrorResponse(errorenum.SomethingError)
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	// bikin nomor increment (no++)
	items := make([]map[string]interface{}, len(results))
	for i, r := range results {
		items[i] = map[string]interface{}{
			"unique_id":       r.UniqueID,
			"name_bug":        r.NameBug,
			"type_bug":        r.TypeBug,
			"description_bug": r.DescriptionBug,
			"created_at":      r.CreatedAt,
			"updated_at":      r.UpdatedAt,
		}
	}

	// kalau di page pertama (cursor_id=0, direction=next), prevCursor harus null
	if cursorID == 0 && direction == "next" {
		prevCursor = nil
	}

	response = payload.NewSuccessResponse(fiber.Map{
		"items":       items,
		"has_more":    hasMore,
		"next_cursor": nextCursor,
		"prev_cursor": prevCursor,
	}, errorenum.OKSuccess)

	return c.Status(fiber.StatusOK).JSON(response)
}
