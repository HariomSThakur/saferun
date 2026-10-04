document.addEventListener("DOMContentLoaded", () => {
  const ignoredFolderNames = new Set([
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "dist", "build", "coverage", ".next", ".nuxt", ".angular", ".gradle", ".terraform", "target",
  ]);
  const folderFilesToUpload = (files) => Array.from(files || []).filter((file) =>
    !(file.webkitRelativePath || file.name).split("/").some((part) => ignoredFolderNames.has(part.toLowerCase())),
  );
  const fileInput = document.querySelector("#archive");
  const folderInput = document.querySelector("#project-files");
  const selectedUpload = document.querySelector("#selected-upload");
  const uploadForm = document.querySelector("#upload-form");
  const uploadError = document.querySelector("#upload-error");
  const submitButtons = Array.from(document.querySelectorAll("#upload-form button[name='scan_mode']"));
  const updateSelection = () => {
    const zip = fileInput?.files?.[0];
    const folder = folderInput?.files;
    const uploadableFolder = folderFilesToUpload(folder);
    const excludedCount = (folder?.length || 0) - uploadableFolder.length;
    if (selectedUpload) {
      selectedUpload.textContent = zip
        ? `Selected ZIP: ${zip.name}`
        : folder?.length
          ? `Selected folder: ${folder[0].webkitRelativePath?.split("/")[0] || "project folder"} (${uploadableFolder.length} project files${excludedCount ? `; ${excludedCount} generated files excluded` : ""})`
          : "No project selected yet.";
    }
  };
  fileInput?.addEventListener("change", () => {
    if (fileInput.files?.length && folderInput) folderInput.value = "";
    updateSelection();
  });
  folderInput?.addEventListener("change", () => {
    if (folderInput.files?.length && fileInput) fileInput.value = "";
    updateSelection();
  });
  if (uploadForm && fileInput && folderInput) {
    uploadForm.addEventListener("submit", async (event) => {
      const zip = fileInput.files?.[0];
      const files = folderFilesToUpload(folderInput.files);
      if (!zip && !files.length) {
        event.preventDefault();
        if (uploadError) {
          uploadError.hidden = false;
          uploadError.textContent = folderInput.files?.length
            ? "This folder contains only generated files that SafeRun excludes. Choose a folder with project source or configuration files."
            : "Choose a ZIP archive or project folder first.";
        }
        return;
      }
      event.preventDefault();
      if (uploadError) uploadError.hidden = true;
      const clickedButton = event.submitter;
      const scanMode = clickedButton?.value === "full_tests" ? "full_tests" : "standard";
      submitButtons.forEach((button) => { button.disabled = true; });
      if (clickedButton) clickedButton.textContent = "Uploading project…";
      try {
        const body = new FormData(uploadForm);
        body.set("scan_mode", scanMode);
        body.delete("archive");
        body.delete("project_files");
        if (zip) {
          body.append("archive", zip, zip.name);
        } else {
          for (const file of files) {
            body.append("project_files", file, file.webkitRelativePath || file.name);
          }
        }
        const response = await fetch(uploadForm.action, {
          method: "POST",
          body,
          credentials: "same-origin",
          redirect: "follow",
        });
        if (response.redirected) {
          window.location.assign(response.url);
          return;
        }
        const message = response.status === 413
          ? "This upload is too large. Keep it under 25 MiB and try again."
          : "SafeRun could not accept this upload. Check the file and try again.";
        throw new Error(message);
      } catch (error) {
        if (uploadError) {
          uploadError.hidden = false;
          uploadError.textContent = error instanceof Error ? error.message : "The upload failed. Please try again.";
        }
        submitButtons.forEach((button) => { button.disabled = false; });
        submitButtons.forEach((button) => {
          button.innerHTML = button.value === "full_tests" ? 'Run full test suite <span aria-hidden="true">→</span>' : "Inspect repository";
        });
      }
    });
  }
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });
});
