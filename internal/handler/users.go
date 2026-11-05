package handler

import (
	"net/http"

	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/service"
)

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request, u *domain.User) {
	out, err := h.svc.ListUsers(r.Context(), u)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type createUserRequest struct {
	Login       string `json:"login"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	Role        string `json:"role"`
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request, u *domain.User) {
	var req createUserRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	out, err := h.svc.CreateUser(r.Context(), u, service.CreateUserInput(req))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (h *Handler) getUser(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.GetUser(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type updateUserRequest struct {
	DisplayName *string `json:"display_name"`
	Role        *string `json:"role"`
	IsActive    *bool   `json:"is_active"`
}

func (h *Handler) updateUser(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req updateUserRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	out, err := h.svc.UpdateUser(r.Context(), u, id, service.UpdateUserInput(req))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.DeleteUser(r.Context(), u, id); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type resetPasswordRequest struct {
	Password string `json:"password"`
}

func (h *Handler) resetPassword(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req resetPasswordRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	if err := h.svc.ResetPassword(r.Context(), u, id, req.Password); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Groups

func (h *Handler) listGroups(w http.ResponseWriter, r *http.Request, u *domain.User) {
	out, err := h.svc.ListGroupsForUser(r.Context(), u)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type groupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request, u *domain.User) {
	var req groupRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	out, err := h.svc.CreateGroup(r.Context(), u, req.Name, req.Description)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (h *Handler) getGroup(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.GetGroup(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type patchGroupRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

func (h *Handler) updateGroup(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req patchGroupRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	out, err := h.svc.UpdateGroup(r.Context(), u, id, req.Name, req.Description)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.DeleteGroup(r.Context(), u, id); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listGroupPermissions(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.ListGroupPermissions(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type setPermissionsRequest struct {
	Permissions []service.PermissionInput `json:"permissions"`
}

func (h *Handler) setGroupPermissions(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req setPermissionsRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	out, err := h.svc.SetGroupPermissions(r.Context(), u, id, req.Permissions)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
