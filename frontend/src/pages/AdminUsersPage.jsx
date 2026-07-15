import { useEffect, useState } from "react";
import { Button, Card, Form, Modal, OverlayTrigger, Table, Tooltip } from "react-bootstrap";
import { createAdminUser, deleteUserById, getAdminUserConnection, getUsers } from "../api";
import AdminAuthGate from "../components/AdminAuthGate";
import { buildHysteriaUri } from "../utils/hysteriaUri";

function formatDate(value) {
  if (!value) return "-";
  const normalized = typeof value === "string" && !/[zZ]|[+-]\d{2}:\d{2}$/.test(value) ? `${value}Z` : value;
  return new Date(normalized).toLocaleString();
}

function SortableHeader({ label, column, sortBy, sortDir, onClick }) {
  const isActive = sortBy === column;
  const icon = isActive ? (sortDir === "asc" ? "bi bi-sort-up" : "bi bi-sort-down") : "bi bi-arrow-down-up";
  return (
    <th role="button" onClick={onClick}>
      <span className="d-inline-flex align-items-center gap-1">
        {label}
        <i className={icon} />
      </span>
    </th>
  );
}

function ActionTooltip({ id, label, children }) {
  return (
    <OverlayTrigger
      placement="top"
      delay={{ show: 0, hide: 0 }}
      container={typeof document !== "undefined" ? document.body : undefined}
      overlay={<Tooltip id={id}>{label}</Tooltip>}
    >
      {children}
    </OverlayTrigger>
  );
}

export default function AdminUsersPage({ notify }) {
  return (
    <AdminAuthGate notify={notify}>
      {(logout) => <AdminUsersContent logout={logout} notify={notify} />}
    </AdminAuthGate>
  );
}

function AdminUsersContent({ logout, notify }) {
  const [rows, setRows] = useState([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [sortBy, setSortBy] = useState("created_at");
  const [sortDir, setSortDir] = useState("desc");
  const [userToDelete, setUserToDelete] = useState(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [copyingUserId, setCopyingUserId] = useState(null);
  const [createdConnectionUri, setCreatedConnectionUri] = useState("");
  const [isCreating, setIsCreating] = useState(false);
  const [form, setForm] = useState({
    email: "",
    first_name: "",
    last_name: "",
    invite_code: ""
  });
  const pageSize = 20;

  const loadPage = async (currentPage, by = sortBy, dir = sortDir) => {
    const result = await getUsers({
      page: currentPage,
      page_size: pageSize,
      sort_by: by,
      sort_dir: dir
    });
    const nextRows = Array.isArray(result.items) ? result.items : Array.isArray(result) ? result : [];
    setRows(nextRows);
    setTotal(Number(result.total || nextRows.length || 0));
    setPage(currentPage);
  };

  useEffect(() => {
    loadPage(1).catch((err) => {
      if (String(err.message).toLowerCase().includes("credentials")) {
        logout();
      }
      notify("danger", err.message);
    });
  }, []);

  const handleSort = (column) => {
    const nextDir = column === sortBy && sortDir === "asc" ? "desc" : "asc";
    setSortBy(column);
    setSortDir(nextDir);
    loadPage(1, column, nextDir).catch((err) => notify("danger", err.message));
  };

  const confirmDeleteUser = async () => {
    if (!userToDelete || isDeleting) return;
    setIsDeleting(true);
    try {
      await deleteUserById(userToDelete.id);
      notify("success", `Пользователь ${userToDelete.email} удален.`);
      setUserToDelete(null);
      await loadPage(1, sortBy, sortDir);
    } catch (err) {
      notify("danger", err.message);
    } finally {
      setIsDeleting(false);
    }
  };

  const copyConnectionUri = async (userId) => {
    setCopyingUserId(userId);
    try {
      const connection = await getAdminUserConnection(userId);
      const uri = buildHysteriaUri(connection);
      await navigator.clipboard.writeText(uri);
      notify("success", "Ссылка для прокси скопирована.");
    } catch (err) {
      notify("danger", err.message);
    } finally {
      setCopyingUserId(null);
    }
  };

  const handleCreateUser = async (event) => {
    event.preventDefault();
    if (isCreating) return;
    setIsCreating(true);
    try {
      const payload = {
        email: form.email.trim(),
        first_name: form.first_name.trim(),
        last_name: form.last_name.trim() || null,
        invite_code: form.invite_code.trim() || null
      };
      const result = await createAdminUser(payload);
      const uri = buildHysteriaUri(result);
      setCreatedConnectionUri(uri);
      notify("success", `Пользователь ${payload.email} создан.`);
      setForm({ email: "", first_name: "", last_name: "", invite_code: "" });
      await loadPage(1, sortBy, sortDir);
    } catch (err) {
      notify("danger", err.message);
    } finally {
      setIsCreating(false);
    }
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <Card>
      <Card.Body>
        <div className="d-flex justify-content-between align-items-center mb-3">
          <Card.Title className="mb-0">Админка: пользователи</Card.Title>
          <Button variant="outline-danger" onClick={logout}>
            Выйти
          </Button>
        </div>

        <Card className="mb-4 bg-light border-0">
          <Card.Body>
            <Card.Subtitle className="mb-3">Ручная регистрация (без подтверждения почты)</Card.Subtitle>
            <Form onSubmit={handleCreateUser}>
              <div className="row g-2">
                <div className="col-md-3">
                  <Form.Control
                    type="email"
                    placeholder="Email"
                    value={form.email}
                    onChange={(e) => setForm((prev) => ({ ...prev, email: e.target.value }))}
                    required
                  />
                </div>
                <div className="col-md-2">
                  <Form.Control
                    placeholder="Имя"
                    value={form.first_name}
                    onChange={(e) => setForm((prev) => ({ ...prev, first_name: e.target.value }))}
                    required
                  />
                </div>
                <div className="col-md-2">
                  <Form.Control
                    placeholder="Фамилия (необяз.)"
                    value={form.last_name}
                    onChange={(e) => setForm((prev) => ({ ...prev, last_name: e.target.value }))}
                  />
                </div>
                <div className="col-md-3">
                  <Form.Control
                    placeholder="Invite-код (необяз.)"
                    value={form.invite_code}
                    onChange={(e) => setForm((prev) => ({ ...prev, invite_code: e.target.value }))}
                  />
                </div>
                <div className="col-md-2">
                  <Button type="submit" className="w-100" disabled={isCreating}>
                    {isCreating ? "Создание..." : "Создать"}
                  </Button>
                </div>
              </div>
              <Form.Text className="text-muted">
                Если invite-код не указан, будет создан служебный код автоматически.
              </Form.Text>
            </Form>
          </Card.Body>
        </Card>

        <div className="table-responsive">
          <Table bordered hover size="sm" className="align-middle mb-0">
            <thead>
              <tr>
                <SortableHeader label="Email" column="email" sortBy={sortBy} sortDir={sortDir} onClick={() => handleSort("email")} />
                <SortableHeader label="Имя" column="first_name" sortBy={sortBy} sortDir={sortDir} onClick={() => handleSort("first_name")} />
                <SortableHeader label="Фамилия" column="last_name" sortBy={sortBy} sortDir={sortDir} onClick={() => handleSort("last_name")} />
                <SortableHeader label="Дата регистрации" column="created_at" sortBy={sortBy} sortDir={sortDir} onClick={() => handleSort("created_at")} />
                <th>Invite код</th>
                <th>Действие</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((user) => (
                <tr key={user.id}>
                  <td>{user.email}</td>
                  <td>{user.first_name}</td>
                  <td>{user.last_name || "-"}</td>
                  <td>{formatDate(user.created_at)}</td>
                  <td>{user.invite_code}</td>
                  <td>
                    <div className="d-flex flex-wrap gap-2">
                      <ActionTooltip id={`user-uri-${user.id}`} label="Скопировать hysteria2:// ссылку для прокси">
                        <Button
                          size="sm"
                          variant="outline-primary"
                          disabled={copyingUserId === user.id}
                          onClick={() => copyConnectionUri(user.id)}
                        >
                          <i className="bi bi-link-45deg" />
                        </Button>
                      </ActionTooltip>
                      <Button
                        size="sm"
                        variant="outline-danger"
                        onClick={() => setUserToDelete(user)}
                      >
                        Удалить
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
        <div className="d-flex flex-wrap gap-2 justify-content-between align-items-center mt-3">
          <div>Страница {page} / {totalPages} (всего {total})</div>
          <div className="d-flex gap-2">
            <Button size="sm" variant="outline-secondary" disabled={page <= 1} onClick={() => loadPage(page - 1)}>
              Назад
            </Button>
            <Button size="sm" variant="outline-secondary" disabled={page >= totalPages} onClick={() => loadPage(page + 1)}>
              Вперед
            </Button>
          </div>
        </div>
        <Modal show={Boolean(userToDelete)} onHide={() => !isDeleting && setUserToDelete(null)} centered>
          <Modal.Header closeButton={!isDeleting}>
            <Modal.Title>Подтверждение удаления</Modal.Title>
          </Modal.Header>
          <Modal.Body>
            {userToDelete ? `Удалить пользователя ${userToDelete.email}? Действие необратимо.` : ""}
          </Modal.Body>
          <Modal.Footer>
            <Button variant="secondary" onClick={() => setUserToDelete(null)} disabled={isDeleting}>
              Отмена
            </Button>
            <Button variant="danger" onClick={confirmDeleteUser} disabled={isDeleting}>
              {isDeleting ? "Удаление..." : "Удалить"}
            </Button>
          </Modal.Footer>
        </Modal>
        <Modal show={Boolean(createdConnectionUri)} onHide={() => setCreatedConnectionUri("")} centered size="lg">
          <Modal.Header closeButton>
            <Modal.Title>Пользователь создан</Modal.Title>
          </Modal.Header>
          <Modal.Body>
            <p className="mb-2">Ссылка для подключения к прокси (Hysteria):</p>
            <Form.Control
              as="textarea"
              rows={4}
              readOnly
              value={createdConnectionUri}
              style={{ fontFamily: "monospace" }}
            />
          </Modal.Body>
          <Modal.Footer>
            <Button
              variant="outline-primary"
              onClick={async () => {
                await navigator.clipboard.writeText(createdConnectionUri);
                notify("success", "Ссылка скопирована.");
              }}
            >
              Скопировать ссылку
            </Button>
            <Button variant="primary" onClick={() => setCreatedConnectionUri("")}>
              Закрыть
            </Button>
          </Modal.Footer>
        </Modal>
      </Card.Body>
    </Card>
  );
}
