(() => {
  document.querySelectorAll("[data-password-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
      const wrapper = button.closest(".password-wrap");
      const input = wrapper?.querySelector("[data-password-input]");
      if (!input) return;
      const reveal = input.type === "password";
      input.type = reveal ? "text" : "password";
      button.textContent = reveal ? "Hide" : "Show";
      button.setAttribute("aria-label", reveal ? "Hide passphrase" : "Show passphrase");
    });
  });

  const strengthInput = document.querySelector("[data-strength-source]");
  if (strengthInput) {
    const checks = {
      length: (value) => value.length >= 12,
      lower: (value) => /[a-z]/.test(value),
      upper: (value) => /[A-Z]/.test(value),
      number: (value) => /[0-9]/.test(value),
      special: (value) => /[^A-Za-z0-9\s]/.test(value),
    };
    const update = () => {
      Object.entries(checks).forEach(([name, check]) => {
        document.querySelector(`[data-rule="${name}"]`)?.classList.toggle("rule-valid", check(strengthInput.value));
      });
    };
    strengthInput.addEventListener("input", update);
    update();
  }

  const lockout = document.querySelector("[data-lockout-seconds]");
  if (lockout) {
    let remaining = Number.parseInt(lockout.dataset.lockoutSeconds || "0", 10);
    const label = lockout.querySelector("[data-lockout-label]");
    const submit = document.querySelector("[data-submit-button]");
    if (submit) submit.disabled = remaining > 0;
    const render = () => {
      if (label) label.textContent = `${remaining} second${remaining === 1 ? "" : "s"}`;
      if (remaining <= 0) {
        if (submit) submit.disabled = false;
        lockout.classList.remove("alert-danger");
        lockout.classList.add("alert-success");
        lockout.textContent = "Lockout ended. You can try logging in again.";
        return;
      }
      remaining -= 1;
      window.setTimeout(render, 1000);
    };
    render();
  }

  const session = document.querySelector("[data-session-expiry]");
  if (session) {
    const expiry = Number.parseInt(session.dataset.sessionExpiry || "0", 10);
    const render = () => {
      const remaining = Math.max(0, expiry - Math.floor(Date.now() / 1000));
      const minutes = Math.floor(remaining / 60);
      const seconds = remaining % 60;
      session.textContent = `${minutes}:${String(seconds).padStart(2, "0")}`;
      if (remaining === 0) {
        window.location.assign("/auth/login");
        return;
      }
      window.setTimeout(render, 1000);
    };
    render();
  }
})();
