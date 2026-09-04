document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".messages .message:not(.sticky)").forEach((el) => {
        setTimeout(() => {
            el.style.transition = "opacity 0.4s ease";
            el.style.opacity = "0";
            setTimeout(() => el.remove(), 400);
        }, 4000);
    });

    document.querySelectorAll("[data-confirm]").forEach((el) => {
        el.addEventListener("click", (event) => {
            const message = el.getAttribute("data-confirm") || "Are you sure?";
            if (!window.confirm(message)) {
                event.preventDefault();
            }
        });
    });

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

    const scroller = document.querySelector("[data-dm-scroll]");
    if (scroller) {
        scroller.scrollTop = scroller.scrollHeight;
    }

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
