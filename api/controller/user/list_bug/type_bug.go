package controller_list_bug

import (
	"github.com/gofiber/fiber/v2"

	domain_listbug "xops-admin/domain/user/list_bug"
	"xops-admin/helper/errorenum"
	"xops-admin/helper/payload"
	"xops-admin/model"
)

type TypeBugHandler struct {
	usecase domain_listbug.BugTypeUseCase
}

func NewTypeBugHandler(u domain_listbug.BugTypeUseCase) *TypeBugHandler {
	return &TypeBugHandler{usecase: u}
}

// Create
func (h *TypeBugHandler) Create(c *fiber.Ctx) error {
	var typeBug model.TypeBug
	var response payload.Response
	if err := c.BodyParser(&typeBug); err != nil {
		response = payload.NewErrorResponse(errorenum.SomethingError)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	if err := h.usecase.Create(c.Context(), &typeBug); err != nil {
		response = payload.NewErrorResponse(errorenum.SomethingError)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	response = payload.NewSuccessResponse(typeBug, errorenum.OKSuccess)
	return c.Status(fiber.StatusCreated).JSON(response)
}

// GetByID
func (h *TypeBugHandler) GetByID(c *fiber.Ctx) error {
	var response payload.Response
	id := c.Params("id")
	typeBug, err := h.usecase.GetByID(c.Context(), id)
	if err != nil {
		response = payload.NewErrorResponse(errorenum.SomethingError)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	response = payload.NewSuccessResponse(typeBug, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)
}

// Update
func (h *TypeBugHandler) Update(c *fiber.Ctx) error {
	var typeBug model.TypeBug
	var response payload.Response
	if err := c.BodyParser(&typeBug); err != nil {
		response = payload.NewErrorResponse(errorenum.SomethingError)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	if err := h.usecase.Update(c.Context(), &typeBug); err != nil {
		response = payload.NewErrorResponse(errorenum.SomethingError)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	response = payload.NewSuccessResponse(typeBug, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)
}

// Delete
func (h *TypeBugHandler) Delete(c *fiber.Ctx) error {
	id := c.Params("id")
	var response payload.Response

	if err := h.usecase.Delete(c.Context(), id); err != nil {
		response = payload.NewErrorResponse(errorenum.SomethingError)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	response = payload.NewSuccessResponse(nil, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)

}

// List
func (h *TypeBugHandler) List(c *fiber.Ctx) error {
	var response payload.Response
	search := c.Query("search")

	results, _, err := h.usecase.List(c.Context(), search)
	if err != nil {
		response = payload.NewErrorResponse(errorenum.SomethingError)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	response = payload.NewSuccessResponse(results, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)

}
