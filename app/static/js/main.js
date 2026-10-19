// TrustVault Frontend Logic - Pure Vanilla JS, Zero External Libraries

function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute("content") : "";
}

function showToast(message, type = "success") {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    container.className = "toast-container";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.remove();
  }, 4000);
}

function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add("active");
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove("active");
  }
}

// Close modals on Escape key
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    document.querySelectorAll(".modal-overlay.active").forEach((m) => m.classList.remove("active"));
  }
});

// Secure API Fetch Wrapper attaching CSRF token
async function secureFetch(url, options = {}) {
  const token = getCsrfToken();
  const headers = options.headers || {};

  if (!headers["X-CSRF-Token"] && token) {
    headers["X-CSRF-Token"] = token;
  }

  options.headers = headers;
  return fetch(url, options);
}

// Verification of Cryptographic Audit Chain (Admin Dashboard)
async function runAuditVerification() {
  const statusEl = document.getElementById("verification-status");
  const btn = document.getElementById("verify-btn");

  if (!statusEl || !btn) return;

  btn.disabled = true;
  btn.textContent = "Verifying SHA-256 Hashes...";

  try {
    const res = await secureFetch("/admin/verify-audit-chain", {
      method: "POST"
    });
    const data = await res.json();

    if (res.ok && data.is_valid) {
      statusEl.className = "badge badge-success";
      statusEl.textContent = "VERIFIED INTACT: Cryptographic chain intact from Genesis block";
      showToast("Audit chain verified successfully! No tampering detected.", "success");
    } else {
      statusEl.className = "badge badge-danger";
      statusEl.textContent = `TAMPERING DETECTED: Compromised log record #${data.compromised_id || "Unknown"}`;
      showToast(`Warning: Audit chain failed verification! ${data.message}`, "error");
    }
  } catch (err) {
    showToast("Error connecting to verification service: " + err.message, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Verify Hash Chain Integrity Now";
  }
}

// Revoke document permission
async function revokePermission(docId, targetUserId, username) {
  if (!confirm(`Are you sure you want to revoke access for ${username}? This terminates their access immediately.`)) {
    return;
  }

  try {
    const res = await secureFetch(`/documents/${docId}/permissions/${targetUserId}`, {
      method: "DELETE"
    });
    const data = await res.json();

    if (res.ok) {
      showToast(`Access for ${username} revoked immediately.`, "success");
      setTimeout(() => location.reload(), 800);
    } else {
      showToast(data.error || "Failed to revoke permission.", "error");
    }
  } catch (err) {
    showToast("Network error: " + err.message, "error");
  }
}

// Soft delete document
async function deleteDocument(docId, title) {
  if (!confirm(`Are you sure you want to delete '${title}'? This will remove access for all users immediately.`)) {
    return;
  }

  try {
    const res = await secureFetch(`/documents/${docId}/delete`, {
      method: "POST"
    });
    const data = await res.json();

    if (res.ok) {
      showToast("Document deleted successfully.", "success");
      setTimeout(() => window.location.href = "/documents/", 800);
    } else {
      showToast(data.error || "Failed to delete document.", "error");
    }
  } catch (err) {
    showToast("Network error: " + err.message, "error");
  }
}
