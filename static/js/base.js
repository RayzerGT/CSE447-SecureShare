// SecureShare base JS - shared UI helpers.
// Embedded/vanilla JS only, per project stack (no external JS frameworks).

document.addEventListener("DOMContentLoaded", () => {
    // Auto-dismiss flash messages after a few seconds.
    document.querySelectorAll(".messages .message").forEach((el) => {
        setTimeout(() => {
            el.style.transition = "opacity 0.4s ease";
            el.style.opacity = "0";
            setTimeout(() => el.remove(), 400);
        }, 4000);
    });

    // Confirm destructive actions (delete post/comment, ban user, etc.)
    document.querySelectorAll("[data-confirm]").forEach((el) => {
        el.addEventListener("click", (event) => {
            const message = el.getAttribute("data-confirm") || "Are you sure?";
            if (!window.confirm(message)) {
                event.preventDefault();
            }
        });
    });

    // Upload page: show a local preview of the chosen image before submitting.
    // The file input is rendered by Django's form, so find it by type rather
    // than expecting a hand-authored attribute on it.
    const zone = document.querySelector("[data-dropzone]");
    const picker = zone && zone.querySelector('input[type="file"]');
    const preview = document.querySelector("[data-image-preview]");
    const placeholder = document.querySelector("[data-image-placeholder]");
    if (picker && preview) {
        picker.addEventListener("change", () => {
            const file = picker.files && picker.files[0];
            if (!file) return;
            preview.src = URL.createObjectURL(file);
            preview.hidden = false;
            if (placeholder) placeholder.hidden = true;
        });
    }

    // DM thread: start scrolled to the newest message, like a real chat.
    const scroller = document.querySelector("[data-dm-scroll]");
    if (scroller) {
        scroller.scrollTop = scroller.scrollHeight;
    }

    // DM composer: grow the textarea with its content, and send on Enter
    // (Shift+Enter for a newline).
    const composer = document.querySelector("[data-dm-composer]");
    if (composer) {
        const grow = () => {
            composer.style.height = "auto";
            composer.style.height = composer.scrollHeight + "px";
        };
        composer.addEventListener("input", grow);
        composer.addEventListener("keydown", (event) => {
            if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                composer.form.requestSubmit();
            }
        });
        grow();
    }
});
