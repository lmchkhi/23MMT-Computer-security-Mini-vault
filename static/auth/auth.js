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
})();