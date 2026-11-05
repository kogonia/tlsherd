package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/service"
)

func (h *Handler) getNotificationSettings(w http.ResponseWriter, r *http.Request, u *domain.User) {
	out, err := h.svc.GetNotificationSettings(r.Context(), u)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) putNotificationSettings(w http.ResponseWriter, r *http.Request, u *domain.User) {
	var in service.PutNotificationSettingsInput
	if !h.decodeJSON(w, r, &in, false) {
		return
	}
	if err := h.svc.PutNotificationSettings(r.Context(), u, in); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) testNotification(w http.ResponseWriter, r *http.Request, u *domain.User) {
	var in service.TestNotificationInput
	if !h.decodeJSON(w, r, &in, false) {
		return
	}
	if err := h.svc.TestNotification(r.Context(), u, in); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listNotificationAccounts(w http.ResponseWriter, r *http.Request, u *domain.User) {
	out, err := h.svc.ListNotificationAccounts(r.Context(), u)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) createNotificationAccount(w http.ResponseWriter, r *http.Request, u *domain.User) {
	var in service.CreateNotificationAccountInput
	if !h.decodeJSON(w, r, &in, false) {
		return
	}
	out, err := h.svc.CreateNotificationAccount(r.Context(), u, in)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (h *Handler) getNotificationAccount(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.GetNotificationAccount(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) putNotificationAccount(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in service.UpdateNotificationAccountInput
	if !h.decodeJSON(w, r, &in, false) {
		return
	}
	out, err := h.svc.UpdateNotificationAccount(r.Context(), u, id, in)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) deleteNotificationAccount(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.DeleteNotificationAccount(r.Context(), u, id); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listNotificationDestinations(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.ListNotificationDestinations(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toDestDTOs(out))
}

func (h *Handler) createNotificationDestination(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in service.DestinationInput
	if !h.decodeJSON(w, r, &in, false) {
		return
	}
	out, err := h.svc.CreateNotificationDestination(r.Context(), u, id, in)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toDestDTO(*out))
}

func (h *Handler) putNotificationDestination(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	destID, ok := h.pathUUID(w, r, "destID")
	if !ok {
		return
	}
	var in service.DestinationInput
	if !h.decodeJSON(w, r, &in, false) {
		return
	}
	out, err := h.svc.UpdateNotificationDestination(r.Context(), u, id, destID, in)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toDestDTO(*out))
}

func (h *Handler) deleteNotificationDestination(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	destID, ok := h.pathUUID(w, r, "destID")
	if !ok {
		return
	}
	if err := h.svc.DeleteNotificationDestination(r.Context(), u, id, destID); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listEventTypes(w http.ResponseWriter, r *http.Request, u *domain.User) {
	if u.Role != domain.RoleAdmin {
		h.fail(w, r, domain.ErrForbidden)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"types":    service.KnownEventTypes(),
		"defaults": service.DefaultNotificationEventTypes,
	})
}

type destDTO struct {
	domain.NotificationDestination
	Config json.RawMessage `json:"config"`
}

func toDestDTO(d domain.NotificationDestination) destDTO {
	return destDTO{NotificationDestination: d, Config: rawOrEmpty(d.Config)}
}

func toDestDTOs(in []domain.NotificationDestination) []destDTO {
	out := make([]destDTO, len(in))
	for i, d := range in {
		out[i] = toDestDTO(d)
	}
	return out
}

type eventNotifyDTO struct {
	domain.Event
	Details       json.RawMessage            `json:"details"`
	NotifyStatus  string                     `json:"notify_status"`
	Notifications []domain.EventNotification `json:"notifications"`
}

func eventNotifyDTOs(in []service.EventWithNotify) []eventNotifyDTO {
	out := make([]eventNotifyDTO, len(in))
	for i, e := range in {
		rows := e.Notifications
		if rows == nil {
			rows = []domain.EventNotification{}
		}
		out[i] = eventNotifyDTO{
			Event: e.Event, Details: rawOrEmpty(e.Details),
			NotifyStatus: e.NotifyStatus, Notifications: rows,
		}
	}
	return out
}

func (h *Handler) pathInt64(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	v := r.PathValue(name)
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		h.badRequest(w, "invalid "+name)
		return 0, false
	}
	return n, true
}
