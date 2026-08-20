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
});
