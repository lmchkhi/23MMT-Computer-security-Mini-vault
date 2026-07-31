(() => {
  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.querySelector(button.dataset.copyTarget || "");
      if (!target) return;
      const value = "value" in target ? target.value : target.textContent;
      try {
        await navigator.clipboard.writeText(value || "");
        const original = button.textContent;
        button.textContent = "Copied";
        window.setTimeout(() => { button.textContent = original; }, 1200);
      } catch {
        target.focus?.();
        target.select?.();
      }
    });
  });

  document.querySelectorAll("[data-tab-group]").forEach((group) => {
    const buttons = group.querySelectorAll("[data-tab-target]");
    const panels = group.querySelectorAll("[data-tab-panel]");
    const activate = (name) => {
      buttons.forEach((button) => button.classList.toggle("active", button.dataset.tabTarget === name));
      panels.forEach((panel) => { panel.hidden = panel.dataset.tabPanel !== name; });
    };
    buttons.forEach((button) => button.addEventListener("click", () => activate(button.dataset.tabTarget)));
    const requested = group.dataset.activeTab;
    activate(requested || buttons[0]?.dataset.tabTarget || "");
  });
})();
